#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the second assumption registry — the ones no model constant can carry.

`scripts/assumption_gate.py` accepts exactly one shape: a Boolean TLA constant
some configuration assigns BOTH WAYS and some reachable definition reads. That
rule is what makes a model assumption falsifiable — you discharge it by running
the other arm — and it is measured, not asserted: `M7-Q2` (does the ROM clear
`WATCHDOG.scratch2` on return from BOOTSEL?) put into `assurance/assumptions.toml`
answers `in the registry but no configuration assigns it`. So does a recorded
board PASS, and so does `tools/emu` fidelity. They are statements about a
platform, a tool or an abstraction, and there is no arm to run.

**Why a second file and not a `class` field on the first.** A discriminator
inside `assumptions.toml` would pick which rules apply, and the rules it would
have to switch off are ALL THREE of the mechanical ones that file has — which
leaves "an entry exists". Measured, on the real gate: an entry for `M7-Q2` there
answers `in the registry but no configuration assigns it`, so the amendment must
disable the orphan rule as well as the both-arms and reachability rules; and the
counterfactual — that gate with the two constant rules skipped for `platform` —
passes `PowerOnClearsScratch2` pinned nine ways with nothing to falsify it.
Deleting a constant from that registry instead reddens it at once, so a second
file makes the misclass a red row rather than a spelling.

The classes differ in how they are DISCHARGED, which is the other half: a model
constant is discharged by a TLC run, an entry here by a board measurement, a
vendor erratum, a source audit or an accepted risk with an owner. Nothing here
can be discharged by anything this repository runs, and on the day it is written
**one of eighteen entries is discharged**. The registry says so rather than
looking populated.

Six rules, and the first is the one that earns the file:

* **candidates are DERIVED, and every one is claimed.** Four derivations, each
  floored where its source exists and it found nothing:
  `slice:` the assumption ids the closed slice's bundle and the design pages
  carry — ten of them, and `docs/authorization-slice.md` measured **zero
  registered** before this file; `model:` every constant of the first registry,
  because a model assumption's own discharge is always a fact about the world;
  `board-only:` the suites `tests/emu.py` refuses by name that
  `scripts/usbip-guest.sh` does not run either — no runner in this tree can pass
  them, so each is a pending board obligation; `unsafe:` every `.rs` whose CODE
  carries the token, which is stage 10's "firmware unsafe invariant" half.
  Each reads a STRUCTURE and not a text: the shim's dict through `ast`, the
  guest's rows through `gate_lines`, Rust with its comments and strings removed.
  The review drove nine legal spellings past the first, text-reading versions.
* **both ways.** A `covers` token no derivation produces is an entry outliving
  its candidate — the shape that leaves a registry looking complete over a
  shorter list.
* **a discharge route and an owner, or the entry is a wish.** Both fields, the
  owner from a closed vocabulary, because "someone should measure this" names
  nobody.
* **a claim of discharge owes evidence.** Anything but `pending` needs artifacts
  that are in the tree; a silicon-class discharge needs the stepping it was taken
  on, a stepping written anywhere here must be a real one whatever the class, and
  a discharge carrying one owes a raw artifact under `assurance/board/` — because
  a rule satisfied by any file that merely exists is satisfied by `README.md`,
  which is what the review reached the hardware axis with.
* **links resolve.** `supports` names registry properties, `depends_on` and
  `refines` name entries here, `discharges` names constants of the first
  registry — and an entry covering `model:X` must discharge `X`, so the two
  registries cannot drift into two answers about the same constant.
* **the page is generated.** `docs/platform-assumptions.md` is written from the
  entries and byte-diffed, so a status cannot move without the diff that says so.
  That is what "not silently" means here: the flip is cheap, its visibility is
  what this buys.

`contradicts` is the one link kind of stage 1B п.3 left out. No pair in this
registry contradicts another, so the field would have no instance — and a rule
whose only exercise is its own mutation is the thing this programme keeps finding
switched off. It goes in when a real pair arrives.
"""

import ast
import pathlib
import re
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parents[1]

REGISTRY = pathlib.Path("assurance/platform.toml")
MODEL_REGISTRY = pathlib.Path("assurance/assumptions.toml")
PROPERTIES = pathlib.Path("assurance/properties.toml")
BUNDLES = pathlib.Path("assurance/bundle")
ARTIFACT = pathlib.Path("docs/platform-assumptions.md")
EMU_SHIM = pathlib.Path("tests/emu.py")
USBIP_GUEST = pathlib.Path("scripts/usbip-guest.sh")
UNSAFE_PAGE = pathlib.Path("docs/unsafe.md")
#: Where a raw board result lands. Empty, and that is the state it is meant to
#: report: a discharge naming a stepping must cite something from here, or any
#: file in the tree that happens to exist stands in for a measurement.
BOARD_EVIDENCE = "assurance/board/"

#: Stage 10's inventory's eleven categories, plus the six the closed slice's own
#: assumption table produced that no hardware table has a row for. The class is
#: what a reader sorts by; it is deliberately NOT what decides whether a row is a
#: board result — the review measured that keying the hardware axis on
#: [`HARDWARE_CLASSES`] printed 0 over a discharged `tool-fidelity` row whose own
#: route reads "a board recording of the same session".
CLASSES = {
    "reset",
    "memory",
    "flash",
    "boot-rom",
    "otp",
    "trng",
    "timers",
    "multicore-xip",
    "input",
    "display",
    "toolchain",
    "tool-fidelity",
    "tool-tcb",
    "crypto-primitive",
    "model-abstraction",
    "threat-model",
    "build-configuration",
}

#: The classes whose discharge is a measurement on silicon, and so must record
#: the stepping. `toolchain` is not one: the Rust memory model and the linker
#: script are read, not measured. This obliges a stepping; it does not decide who
#: HAS one — a row of any class that records a real stepping is a board result.
HARDWARE_CLASSES = frozenset(
    {"reset", "memory", "flash", "boot-rom", "otp", "trng", "timers", "multicore-xip"}
)

STATUSES = {"pending", "discharged", "accepted-risk", "refuted"}

#: Who can actually do the discharging. `maintainer` is the one that means
#: hardware in this repo — see AGENTS.md's maintainer-only list.
OWNERS = {"maintainer", "contributor", "vendor", "upstream"}

HAND_FIELDS = {
    "id",
    "statement",
    "class",
    "discharge",
    "discharge_owner",
    "status",
    "failure_direction",
}
LINKS = ("depends_on", "refines", "discharges", "supports", "covers")
#: Stage 10's per-assumption list wants a revalidation trigger too, and it is here
#: rather than in [`HAND_FIELDS`] because it is only answerable once: a trigger
#: for a measurement nobody has made is a placeholder, and 17 placeholders are
#: what a required field would produce today. A discharge owes one.
OPTIONAL = set(LINKS) | {"evidence", "board_revision", "revalidated_by"}

#: `PLAT-<AREA>-<NNN>`. The area is free so a new class does not need a new
#: pattern, and the number is what makes the id stable across a re-sort.
ENTRY_ID = re.compile(r"^PLAT-[A-Z]+-\d{3}$")

#: A shipped part with a stepping. Same token `evidence_gate.py` matches, and
#: deliberately the same: a board result named one way there and another way here
#: is two answers to "which silicon".
BOARD_REVISION = re.compile(r"\bRP2350[\s-]+A[0-9]\b")

#: A slice design's assumption id in prose. The bundle carries these as TOML and
#: is the authoritative half; this is the other spelling, because a design page
#: is written before its bundle exists. Narrow on purpose — a looser token reads
#: `SEC-FIDO-001`, `TM-HOST-GATES` and `RP2350-A2` as assumption ids.
SLICE_ID = re.compile(r"\bAS-[A-Z]+-\d+\b")

#: Every page under `docs/`, globbed. A two-name list was the first version and
#: the review drove it: a `docs/store-slice.md` carrying `AS-STORE-1` produced no
#: candidate and owed no entry, silently. A design page is written before its
#: bundle exists, which is the whole reason this half is here.
DESIGN_ROOT = pathlib.Path("docs")

#: The token, on source with comments and string literals REMOVED — which is the
#: rule, not the regex. The review measured the regex alone over raw text: 4 of
#: the 12 files it produced carry the word only in a line saying there is no
#: `unsafe` in them, and a fifth is a code generator emitting the word inside a
#: string. Stripping first means no form has to be enumerated: `unsafe {`,
#: `unsafe fn`, `unsafe impl`, `unsafe extern` and the 2024 `#[unsafe(…)]`
#: attribute all survive it, and prose does not.
UNSAFE = re.compile(r"\bunsafe\b")

#: First-party Rust is every `.rs` EXCEPT these, which is what the rule always
#: meant. A whitelist of roots was the first version and the review drove it: a
#: new top-level crate — `rsk-wipe/`'s own shape — was invisible. `third_party/`
#: is out for the reason `citation_gate.py` gives: a vendored fork's `unsafe` is
#: its author's invariant, not this tree's.
UNSAFE_EXCLUDED = ("third_party/",)

GENERATED_BY = "Generated by scripts/platform_gate.py --write"


def _toml(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))


def slice_candidates(root):
    """Assumption ids the closed slices declare, from both spellings.

    The bundle is structured — `[[assumption]] id` — and is where a slice's
    assumptions actually live once it closes. The design page is prose and comes
    first. Taking only the bundle would let a design table sit unregistered until
    someone closed the slice; taking only the prose would miss `TCB-1`/`TCB-2`,
    which no `AS-` pattern matches.
    """
    found = {}
    for path in sorted((root / BUNDLES).rglob("*.toml")):
        doc = _toml(path)
        for entry in doc.get("assumption", []):
            name = str(entry.get("id", "")).strip()
            if name:
                found.setdefault(name, str(path.relative_to(root)))
    for page in sorted((root / DESIGN_ROOT).rglob("*.md")):
        for name in SLICE_ID.findall(page.read_text(errors="replace")):
            found.setdefault(name, str(page.relative_to(root)))
    return found


def model_candidates(root):
    """Every constant of the first registry.

    All of them, not the ones whose `discharged_by` says "board": a model
    assumption is by construction a fact the model cannot establish, so its own
    discharge is always a statement about the world outside it. Reading the
    prose for a board-shaped word would be a rule bypassed by writing "silicon".
    """
    doc = _toml(root / MODEL_REGISTRY)
    return {
        str(entry["constant"]): str(MODEL_REGISTRY)
        for entry in doc.get("assumption", [])
        if entry.get("constant")
    }


def emu_refusals(root):
    """The suites `tests/emu.py` refuses by name, with the reason it gives.

    Read through `ast`, not a regex over the source. The regex was the first
    version and the review drove four legal spellings past it — single quotes,
    an implicit concatenation across lines, an f-string, and an empty reason —
    each of which parses, and none of which this tree has a formatter to rule
    out. A literal is what the shim actually has, so a literal is what is read.
    """
    tree = ast.parse((root / EMU_SHIM).read_text(encoding="utf-8"))
    for node in tree.body:
        targets = getattr(node, "targets", [])
        if not any(isinstance(t, ast.Name) and t.id == "UNSUPPORTED" for t in targets):
            continue
        if not isinstance(node.value, ast.Dict):
            break
        out = {}
        for key, value in zip(node.value.keys, node.value.values):
            try:
                name = ast.literal_eval(key)
            except ValueError:
                continue
            try:
                reason = ast.literal_eval(value)
            except ValueError:
                # An f-string has no literal value; the KEY is what is derived
                # from, and a suite with an unreadable reason still owes an entry.
                reason = "no literal reason"
            out[str(name)] = str(reason)
        return out
    return {}


def board_only_candidates(root):
    """Refused by the emulator AND not run by the USB/IP guest: no runner at all.

    The guest names its suites two ways — `tests/02_*.py` as a glob and
    `tests/73_otp_keyboard.py` in full — so the match is on the `tests/NN_`
    prefix, which is the head of both. A suite the guest reaches through a
    variable would be over-reported here, and that direction is the safe one: an
    obligation registered that a runner already covers, never the reverse.

    The guest's CODE, not its text. Reading it whole was the first version and
    the review drove it both ways: a comment naming a board-only suite made its
    obligation disappear, and a comment naming a registered one turned a live
    obligation red with "no derivation produces it" — where the fix reads as
    deleting the row. `gate_lines` is imported here for exactly this and was not
    being used.
    """
    guest = "\n".join(
        gate_lines.split_at_comment(line)[0]
        for line in (root / USBIP_GUEST).read_text(encoding="utf-8").splitlines()
    )
    return {
        name: f"{EMU_SHIM} UNSUPPORTED ({reason})"
        for name, reason in emu_refusals(root).items()
        if f"tests/{name.split('_')[0]}_" not in guest
    }


def unsafe_candidates(root):
    """Every `.rs` whose CODE carries the token, which `docs/unsafe.md` enumerates."""
    return {
        str(rel): f"the token in {rel}, enumerated by {UNSAFE_PAGE}"
        for rel in sorted(gate_lines.tree_files(root))
        if rel.suffix == ".rs"
        and not str(rel).startswith(UNSAFE_EXCLUDED)
        and UNSAFE.search(gate_lines.rust_code((root / rel).read_text(errors="replace")))
    }


def candidates(root):
    """namespace:key -> where the derivation found it."""
    out = {}
    for prefix, found in (
        ("slice", slice_candidates(root)),
        ("model", model_candidates(root)),
        ("board-only", board_only_candidates(root)),
        ("unsafe", unsafe_candidates(root)),
    ):
        for key, where in found.items():
            out[f"{prefix}:{key}"] = where
    return out


#: Below this a derivation found none of a source that is there — the
#: loop-over-an-empty-set shape. Each is 1 and not a transcribed count: what
#: ratchets the sets is the both-ways rule, which turns a source that stopped
#: being read into one unclaimed-`covers` message per entry that named it.
FLOORS = {"slice": 1, "model": 1, "board-only": 1, "unsafe": 1}


def entries(root, findings):
    """The registry's entries by id, with the shape rules applied."""
    doc = _toml(root / REGISTRY)
    for key in sorted(set(doc) - {"assumption"}):
        findings.append(
            f"{REGISTRY}: top-level `{key}` — the file holds `[[assumption]]`"
            " tables and nothing else"
        )
    out = {}
    for entry in doc.get("assumption", []):
        name = str(entry.get("id", "")).strip()
        if not ENTRY_ID.match(name):
            findings.append(
                f"{REGISTRY}: entry id {name or '(none)'!r} is not `PLAT-AREA-NNN`"
            )
            continue
        if name in out:
            findings.append(f"{name}: a second entry under the same id")
            continue
        out[name] = entry
    return out


def check_shape(name, entry, findings):
    """The fields only a person can write, and the closed vocabularies."""
    missing = HAND_FIELDS - set(entry)
    if missing:
        findings.append(f"{name}: is missing {sorted(missing)}")
    for key in sorted(set(entry) - HAND_FIELDS - OPTIONAL):
        findings.append(
            f"{name}: `{key}` is not a field of this registry — the hand-written"
            f" set is {sorted(HAND_FIELDS)} plus {sorted(OPTIONAL)}"
        )
    if entry.get("class") not in CLASSES:
        findings.append(
            f"{name}: class {entry.get('class')!r} is not one of {sorted(CLASSES)}"
        )
    if entry.get("status") not in STATUSES:
        findings.append(
            f"{name}: status {entry.get('status')!r} is not one of {sorted(STATUSES)}"
        )
    if entry.get("discharge_owner") not in OWNERS:
        findings.append(
            f"{name}: discharge_owner {entry.get('discharge_owner')!r} is not one"
            f" of {sorted(OWNERS)} — an obligation nobody owns is a wish"
        )
    if not str(entry.get("discharge", "")).strip():
        findings.append(
            f"{name}: no discharge route — an entry that cannot say what would"
            " settle it can never stop being pending"
        )


def check_evidence(root, name, entry, findings):
    """A status other than `pending` owes artifacts, and a board owes a stepping."""
    status = entry.get("status")
    evidence = entry.get("evidence", [])
    evidence = evidence if isinstance(evidence, list) else [evidence]
    board = str(entry.get("board_revision", "")).strip()
    # Whatever the class. Gating this on HARDWARE_CLASSES was the first version,
    # and the review put "a red Pico 2 I had lying around" in an `input` row.
    if board and not BOARD_REVISION.search(board):
        findings.append(
            f"{name}: board_revision {board!r} names no RP2350 stepping —"
            " a part with a revision, not a description of a desk"
        )
    if status in ("discharged", "refuted"):
        if not evidence:
            findings.append(
                f"{name}: status {status!r} with no `evidence` — a discharge"
                " claim with nothing behind it is the status moving on its own"
            )
        for rel in evidence:
            if not (root / str(rel)).exists():
                findings.append(
                    f"{name}: evidence {rel!r} is not in the tree"
                )
        if not str(entry.get("revalidated_by", "")).strip():
            findings.append(
                f"{name}: status {status!r} with no `revalidated_by` — a settled"
                " assumption with no trigger stays settled through the change"
                " that unsettles it"
            )
        if entry.get("class") in HARDWARE_CLASSES and not board:
            findings.append(
                f"{name}: a {entry.get('class')} discharge records no"
                " `board_revision` — a platform result names the platform it"
                " was taken on"
            )
        if board and not any(
            str(rel).startswith(BOARD_EVIDENCE) for rel in evidence
        ):
            findings.append(
                f"{name}: a discharge on {board!r} cites no artifact under"
                f" {BOARD_EVIDENCE} — a rule met by any file that merely exists"
                " is met by README.md, which is not a board result"
            )
    elif evidence or board or entry.get("revalidated_by"):
        findings.append(
            f"{name}: status {status!r} carries evidence, a board revision or a"
            " revalidation trigger — an artifact nothing rests on is decoration,"
            " and the entry still reads as undischarged"
        )


def check_links(name, entry, ids, properties, constants, findings):
    """Every link resolves, and `covers`/`discharges` agree about a constant."""
    for kind, universe, what in (
        ("depends_on", ids, "an entry of this registry"),
        ("refines", ids, "an entry of this registry"),
        ("discharges", constants, f"a constant of {MODEL_REGISTRY}"),
        ("supports", properties, f"a property of {PROPERTIES}"),
    ):
        for target in entry.get(kind, []):
            if target not in universe:
                findings.append(f"{name}: {kind} {target!r} is not {what}")
            elif kind in ("depends_on", "refines") and target == name:
                findings.append(f"{name}: {kind} names itself")
    discharges = set(entry.get("discharges", []))
    covered = {c.split(":", 1)[1] for c in entry.get("covers", []) if c.startswith("model:")}
    for constant in sorted(covered - discharges):
        findings.append(
            f"{name}: covers model:{constant} but does not discharge it — the"
            " entry claiming a model constant is the one that says what settles it"
        )
    for constant in sorted(discharges - covered):
        findings.append(
            f"{name}: discharges {constant!r} without covering `model:{constant}` —"
            " then the constant's candidate is claimed by some other entry and the"
            " two registries hold two answers about it"
        )


def check_bundles(root, ids, findings):
    """A bundle's assumption is registered, and its own `registered` field says so.

    The field is hand-written and was `"no"` on eight of ten rows the day this
    registry did not exist. Derived here rather than read, because a claim about
    a registry that the registry does not have to agree with is the copy this
    tree keeps finding rotted.
    """
    claimed = {
        target
        for entry in ids.values()
        for target in entry.get("covers", [])
        if target.startswith("slice:")
    }
    for path in sorted((root / BUNDLES).glob("*.toml")):
        rel = path.relative_to(root)
        for entry in _toml(path).get("assumption", []):
            name = str(entry.get("id", "")).strip()
            if not name:
                continue
            registered = f"slice:{name}" in claimed
            written = str(entry.get("registered", "")).strip().lower()
            if not written:
                findings.append(f"{rel}: assumption {name} carries no `registered`")
            elif written.startswith("yes") != registered:
                findings.append(
                    f"{rel}: assumption {name} says registered={written[:20]!r} and"
                    f" {REGISTRY} {'does' if registered else 'does not'} claim it"
                )


def audit(root):
    """(findings, one-line summary) for the registry, its candidates and its page."""
    root = pathlib.Path(root)
    findings = []
    found = candidates(root)
    for prefix, floor in sorted(FLOORS.items()):
        seen = sum(1 for key in found if key.startswith(f"{prefix}:"))
        if seen < floor:
            findings.append(
                f"the `{prefix}:` derivation found {seen} candidate(s), below its"
                f" floor of {floor} — its source is there and it read none of it,"
                " which looks exactly like a tree with nothing to register"
            )

    registered = entries(root, findings)
    properties = {
        str(row.get("id"))
        for row in _toml(root / PROPERTIES).get("property", [])
    }
    constants = set(model_candidates(root))

    owner = {}
    for name, entry in sorted(registered.items()):
        check_shape(name, entry, findings)
        check_evidence(root, name, entry, findings)
        check_links(name, entry, registered, properties, constants, findings)
        for target in entry.get("covers", []):
            if target not in found:
                findings.append(
                    f"{name}: covers {target!r}, which no derivation produces —"
                    " either the candidate is gone and the entry outlived it, or"
                    " the reader that found it stopped reading"
                )
            elif target in owner:
                findings.append(
                    f"{target} is claimed by both {owner[target]} and {name}"
                )
            else:
                owner[target] = name
    for target in sorted(set(found) - set(owner)):
        findings.append(
            f"{target}: derived from {found[target]} and claimed by no entry —"
            " register it or say here why it is not an assumption"
        )

    check_bundles(root, registered, findings)

    try:
        want = render(root, registered)
    except (OSError, ValueError, KeyError) as error:
        findings.append(f"{ARTIFACT} cannot be generated: {error}")
    else:
        path = root / ARTIFACT
        got = path.read_text(encoding="utf-8") if path.is_file() else ""
        if got != want:
            findings.append(
                f"{ARTIFACT} is not what the generator writes — run"
                " `python scripts/platform_gate.py --write` and commit the result."
                " A status that moves without this diff is a status that moved"
                " silently"
            )

    counts = {s: sum(1 for e in registered.values() if e.get("status") == s) for s in sorted(STATUSES)}
    summary = (
        f"platform-gate: ok — {len(registered)} assumption(s) over {len(found)}"
        " derived candidate(s); "
        + ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    )
    return findings, summary


def render(root, registered=None):
    """`docs/platform-assumptions.md` as the tree makes it."""
    root = pathlib.Path(root)
    registered = entries(root, []) if registered is None else registered
    found = candidates(root)
    rows = sorted(registered.items())
    pending = [n for n, e in rows if e.get("status") == "pending"]
    discharged = [n for n, e in rows if e.get("status") == "discharged"]
    board = [n for n, e in rows if e.get("discharge_owner") == "maintainer"]
    out = [
        "<!-- SPDX-License-Identifier: AGPL-3.0-only -->",
        "<!-- Copyright (C) 2026 RS-Key contributors -->",
        f"<!-- {GENERATED_BY} — do not edit by hand -->",
        "",
        "# Platform assumptions",
        "",
        "The assumptions no model constant can carry. `assurance/assumptions.toml`"
        " holds the other kind — a Boolean TLA constant a configuration assigns"
        " both ways — and refuses these by construction: `M7-Q2` put there answers"
        " `in the registry but no configuration assigns it`, and so does a board"
        " PASS, and so does emulator fidelity. They are statements about a"
        " platform, a tool or an abstraction, and there is no other arm to run.",
        "",
        f"**Discharged: {len(discharged)} of {len(rows)}.** That number is the"
        " point of the page. Everything else is an obligation with an owner and a"
        " named route, and none of it is evidence about anything yet.",
        "",
        "## What discharges what",
        "",
        f"Nothing in this repository can discharge {len(board)} of these rows:"
        " their route ends at a board, and AGENTS.md puts flashing and every"
        " board operation with the maintainer. A row moves off `pending` only"
        " with artifacts in the tree; a silicon-class row additionally with the"
        " stepping it was taken on, any row naming a stepping must name a real"
        f" one, and a row naming one owes a capture under `{BOARD_EVIDENCE}` —"
        " because a rule met by any file that merely exists is met by a README.",
        "",
        f"The candidates are DERIVED — {len(found)} of them, from the slice"
        " bundles and design pages, the model registry, the suites no runner in"
        " this tree can pass, and the first-party `.rs` carrying `unsafe`. An"
        " unclaimed candidate reddens `scripts/platform_gate.py`; so does a claim"
        " on a candidate that no longer exists.",
        "",
        "## The registry",
        "",
        "| ID | Class | Statement | Status | Discharged by | Owner | Supports |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, entry in rows:
        supports = ", ".join(f"`{p}`" for p in entry.get("supports", [])) or "—"
        out.append(
            f"| `{name}` | `{entry.get('class')}` | {entry.get('statement')} |"
            f" **{entry.get('status')}** | {entry.get('discharge')} |"
            f" {entry.get('discharge_owner')} | {supports} |"
        )
    out += [
        "",
        "## The graph",
        "",
        "Stage 1B п.3's link vocabulary, less `contradicts`: no pair here"
        " contradicts another, and a link kind with no instance is a rule whose"
        " only exercise is its own mutation.",
        "",
        "| From | Link | To |",
        "|---|---|---|",
    ]
    edges = [
        (name, kind, target)
        for name, entry in rows
        for kind in ("depends_on", "refines", "discharges")
        for target in entry.get(kind, [])
    ]
    for name, kind, target in edges:
        out.append(f"| `{name}` | `{kind}` | `{target}` |")
    out += [
        "",
        f"`supports` is in the table above, on {sum(1 for _, e in rows if e.get('supports'))}"
        f" of {len(rows)} rows. A property it names is CONDITIONAL on that row"
        " while the row is pending; nothing here upgrades a property's evidence.",
        "",
        "## What this page may not be read as",
        "",
        f"- that any of these {len(rows)} statements is known to be true —"
        f" {len(pending)} are `pending`, which means no artifact in this tree"
        " records a result for them. One of those rows names a run that HAPPENED"
        " and whose capture was never committed, which is a different state and"
        " says so in its own discharge route.",
        "- that the list is complete. Four derivations produce it, and stage 10's"
        " inventory names eleven categories — a category with no candidate source"
        " is a category this page cannot see.",
        "- that a discharged row makes a property proved. It removes a condition;"
        " the property's own evidence is `docs/assurance-vector.md`'s.",
        "",
    ]
    return "\n".join(out)


def run(root, write=False):
    if write:
        (root / ARTIFACT).write_text(render(root), encoding="utf-8")
        print(f"platform-gate: wrote {ARTIFACT}")
        return 0
    findings, summary = audit(root)
    if findings:
        print("platform-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: platform_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
