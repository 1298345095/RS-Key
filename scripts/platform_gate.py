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
can be discharged by anything this repository runs, and **only a small minority
of entries is discharged at all**. The count is DERIVED — [`run`] prints it on a
GREEN literal run and [`render`] opens the generated page with it — because the
typed copy that stood here read `two of thirty-three` against a registry that had
grown past sixty, and no rule holds a number a docstring states. Measured, the
"prints it on every run" this sentence used to claim was false in two directions
and [`main`] was the wrong function: `--write` prints `wrote …` and returns
before the audit, and a red run prints findings on stderr and returns 1. The page
is the copy a reader who never runs the gate sees, which is why it is generated
and not typed.

Seven rules, and the first is the one that earns the file:

* **candidates are DERIVED, and every one is claimed.** Five derivations, each
  floored where its source exists and it found nothing:
  `slice:` the assumption ids the closed slice's bundle and the design pages
  carry — ten of them, and `docs/authorization-slice.md` measured **zero
  registered** before this file; `model:` every constant of the first registry,
  because a model assumption's own discharge is always a fact about the world;
  `board-only:` the suites `tests/emu.py` refuses by name that
  `scripts/usbip-guest.sh` does not run either — no runner in this tree can pass
  them, so each is a pending board obligation; `unsafe:` every `.rs` whose CODE
  carries the token, which is stage 10's "firmware unsafe invariant" half;
  `backend:` every semantic a crate-ledger row declares its model ABSTRACTS —
  the anchor for a row that no other derivation reaches ([`backend_candidates`]).
  Each reads a STRUCTURE and not a text: the shim's dict through `ast`, the
  guest's rows through `gate_lines`, Rust with its comments and strings removed,
  the ledger's `abstracts` as a list and not its `gap` prose.
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
  which is what the review reached the hardware axis with. That sentence then
  stood over the hardware axis ALONE for as long as it was written down: on every
  other row `evidence = ["README.md"]` was exit 0, measured, and
  `PLAT-STORE-003`'s own discharge prose records it. [`PROSE_PAGE`] is the other
  axis's half of it, and it is a weaker rule than the board one — the comment
  there says which attacks it does not stop rather than leaving them to be found.
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
import subprocess
import sys
import tomllib

import claims_gate
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
#: The crate coverage ledger. A `state-partial` row names a model and the gap it
#: leaves; [`backend_candidates`] reads the STRUCTURED half of that gap.
CRATE_LEDGER = pathlib.Path("assurance/crates.toml")
#: Where a raw board result lands, and where every maintainer-owned row's RECORD
#: lives whether or not the run has happened: a discharge naming a stepping must
#: cite something from here, or any file in the tree that happens to exist stands
#: in for a measurement. See [`check_board_records`] for what a record must say.
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

#: A shipped part with a stepping, MENTIONED. `evidence_gate.py` searches a
#: bundle's every leaf with it, because a stepping the evidence depends on turns
#: up in prose; the declaration itself is [`names_a_stepping`]'s.
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


def names_a_stepping(value) -> bool:
    """Whether `value` IS a board revision, rather than mentioning one.

    Both registries that ask "which silicon" call THIS, and not a second copy of
    the token: `re.compile` returns the cached object for the same pattern text,
    so an identity test over two `BOARD_REVISION`s passes over a copy-paste and
    holds nothing. A function has no such cache.

    Whole value, because `search` over an otherwise free field takes "a red Pico
    2 (an RP2350 A2) I had lying around" and publishes it as a board result. Which
    steppings EXIST is Raspberry Pi's roster and not this tree's, so `RP2350 A9`
    is a part with a revision here.
    """
    return bool(BOARD_REVISION.fullmatch(str(value).strip()))


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


def backend_candidates(root):
    """Every semantic a crate-ledger row declares its model ABSTRACTS.

    The `abstracts` LIST, never the `gap` prose beside it. A regex over the prose
    was the obvious first reading and it is the shape this module refuses
    everywhere else: `rsk-store`'s gap sentence names six mechanics in running
    text, and which of the six are obligations is a decision, not a noun phrase a
    pattern can pick out. So the decision is written down as a list, in the ledger
    rather than here, and the both-ways rule does the rest -- a row deleted from
    `assurance/platform.toml` alone leaves its semantic claimed by nobody.

    Keyed `<crate>/<semantic>` because a semantic name is only unique per crate,
    and read for EVERY class: `abstracts` on a `pure` row would be a modelling
    claim in the wrong place, and producing its candidate is what says so.
    """
    doc = _toml(root / CRATE_LEDGER).get("crate", {})
    return {
        f"{crate}/{semantic}": f"{CRATE_LEDGER} [{crate}] abstracts"
        for crate, entry in sorted(doc.items())
        for semantic in entry.get("abstracts", [])
        if str(semantic).strip()
    }


def candidates(root):
    """namespace:key -> where the derivation found it."""
    out = {}
    for prefix, found in (
        ("slice", slice_candidates(root)),
        ("model", model_candidates(root)),
        ("board-only", board_only_candidates(root)),
        ("unsafe", unsafe_candidates(root)),
        ("backend", backend_candidates(root)),
    ):
        for key, where in found.items():
            out[f"{prefix}:{key}"] = where
    return out


#: Below this a derivation found none of a source that is there — the
#: loop-over-an-empty-set shape. Each is 1 and not a transcribed count: what
#: ratchets the sets is the both-ways rule, which turns a source that stopped
#: being read into one unclaimed-`covers` message per entry that named it.
FLOORS = {"slice": 1, "model": 1, "board-only": 1, "unsafe": 1, "backend": 1}


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


#: The suffix a page of prose has here, and the one kind of file a discharge may
#: NOT cite. Everything else is allowed — source, a model, a configuration, a
#: recorded log, a data table — because the defect this closes is narrow and
#: named: `check_evidence` accepted any path that exists, so
#: `evidence = ["README.md"]` on a `model-abstraction` discharge was **exit 0**,
#: measured on this tree before this rule. The board axis already refused that
#: shape ([`BOARD_EVIDENCE`]), and refused it only where the row records a
#: `board_revision`, so the module's own sentence — "a rule met by any file that
#: merely exists is met by `README.md`" — stood unenforced over every row that
#: records none, which today is all of them: `grep -c '^board_revision'` over the
#: registry answers zero, because no discharge here has yet been taken on silicon.
#:
#: WHY THIS KIND. A hand-written page RESTATES a claim; it does not settle one.
#: The registry already has the field for a restatement and requires it —
#: `discharge` — so a page in `evidence` is the same sentence filed twice, and
#: the row then reads as settled by a paragraph someone wrote.
#:
#: A GENERATED page is not that, and the exemption is DERIVED rather than listed:
#: `claims_gate.generated_pages` reads every gate's own `ARTIFACT`/`GENERATED_BY`
#: pair, so `docs/assurance-matrix.md` — `PLAT-BUILD-001`'s second artifact — is
#: evidence because `matrix_gate.py` writes it from data, while a page that
#: merely SAYS it was generated is not (that gate's own drive: three self-exempt
#: spellings at exit 0). A blanket "no `.md`" would have reddened an honestly
#: discharged row, which is the false red this half exists to avoid.
#:
#: That mapping is asked through [`claims_gate.is_generated`] and not read here,
#: because reading it here read the KEY and stopped — the claim without the
#: agreement, which is strictly weaker than the gate the mapping comes from.
#: Measured: `docs/assurance-matrix.md` with its own header line deleted, a page
#: `matrix_gate.py` claims and no longer marks, was **exit 0** as evidence.
#:
#: NOR THE PAGE THIS GATE WRITES, which the carve-out let straight back in:
#: [`ARTIFACT`] is rendered from this registry and [`render`] emits every row's
#: `discharge` verbatim, so `PLAT-STORE-003` `discharged` with
#: `evidence = ["docs/platform-assumptions.md"]` was **exit 0** — the row citing
#: its own restatement. [`circular`] is that clause, and it is not `ARTIFACT`
#: alone: `docs/assurance-vector.md` names 67 of these rows, because
#: `evidence_gate.py` renders it partly from this registry, and citing it is the
#: same loop one hop out.
#:
#: EVERY path, not one of them. "At least one artifact" leaves the reviewer's
#: obvious move open — append `README.md` to a row that already cites three real
#: files and nothing sees it — and this module already refuses decoration in the
#: other direction ("an artifact nothing rests on is decoration").
#:
#: WHAT IT DOES NOT CHECK, said plainly because no shape rule can check
#: RELEVANCE and pretending otherwise is the claim inflation this registry
#: exists to refuse:
#: * not relevance. `evidence = ["deny.toml"]` on a `model-abstraction` discharge
#:   is still exit 0, measured. The rule refuses a KIND of file, never an
#:   unrelated one, and a reviewer reading this row still has to read the file.
#: * not `.txt`. `formal/floors.txt` is a verdict table and legitimate evidence
#:   for a run claim, so the suffix cannot stand for "prose" in general.
#: * not a generator that lies about what it writes. The carve-out is rooted in a
#:   DECLARATION — nothing here imports or runs a `*_gate.py` — so appending an
#:   `ARTIFACT`/`GENERATED_BY` pair to a script that generates nothing still
#:   mints an exemption. Measured on `scripts/spdx_gate.py`, which has neither
#:   and no `--write` at all: four appended lines made `evidence = ["README.md"]`
#:   legal registry-wide, exit 0. What the header half above costs that move is a
#:   second edit — the page must carry the marker too, so `README.md` has to be
#:   rewritten as well as named. Closing it outright means executing every other
#:   gate's renderer from this row, and that is a bigger thing than it buys.
#: * not the strong form. What makes [`BOARD_EVIDENCE`] work is that
#:   `assurance/board/<ID>.toml` is a file this gate SEPARATELY VALIDATES, field
#:   by field, against the row. The non-hardware analogue was measured and
#:   rejected: tying evidence to the row's own candidate turns `PLAT-CRED-004`
#:   RED — none of its three artifacts names its `covers` key `AS-CRED-5` or its
#:   own id — and `PLAT-BUILD-001`'s `firmware/Cargo.toml` names neither
#:   `AS-AUTH-2` nor `AlwaysUvShipped`, leaving only the generated page to tie
#:   the row to itself, which is circular. The real strong form is a validated
#:   `assurance/discharge/<ID>.toml` per row, and its cost is a record, a field
#:   contract, a floor and a mutation table for three live discharges. That is
#:   the shape to take when the count grows, not at three.
PROSE_PAGE = ".md"


def in_tree(rel, tree):
    """Whether `rel` is a file this checkout HAS, spelled the way it spells it.

    `(root / rel).exists()` was the first version and it answered two questions
    this rule never asked. A DIRECTORY passed: `evidence = ["docs"]` was **exit
    0**, which is this module's own "met by `README.md`" sentence with "the
    directory `README.md` sits in" substituted. And so did a spelling that is not
    in the tree at all: APFS folds case while [`PROSE_PAGE`] does not, so
    `evidence = ["README.MD"]` — the literal page the whole rule exists to refuse
    — was exit 0 on the machine this is developed on, and would have gone red on
    a case-sensitive runner as `is not in the tree`, which is the right colour for
    the wrong reason. `gate_lines.tree_files` is git's own listing: case-exact,
    with no directories in it, so both spellings go one colour on both.
    """
    return pathlib.Path(str(rel)) in tree


def hand_written(root, rel, generated):
    """Whether `rel` is a page of prose rather than an artifact.

    Case-folded, because a suffix is a spelling: [`in_tree`] has already settled
    that the path is git's own, so what is left to ask is what KIND of file it
    is, and `docs/UPPER.MD` is a page.

    `generated` is [`claims_gate.generated_pages`]'s mapping, computed once by
    [`audit`] and passed in: it opens every `scripts/*_gate.py`, and calling it
    per entry read them once for each of the registry's rows. What decides is
    that gate's own [`claims_gate.is_generated`] rather than this module's
    reading of its mapping — the key without the header was the weaker half of
    the same test, over the same data.
    """
    if not str(rel).lower().endswith(PROSE_PAGE):
        return False
    text = claims_gate.normalise((root / str(rel)).read_text(errors="replace"))
    return not claims_gate.is_generated(rel, text, generated)


def circular(root, name, rel, generated):
    """Whether `rel` is this registry, or a page rendered from it that names `name`.

    A row cannot be settled by a copy of itself. [`ARTIFACT`] is named outright
    because this gate writes it FROM this registry, whatever it happens to print
    there; so is [`REGISTRY`], the row's own home.

    The derived half is the one that answers "or any page generated from this
    registry": a generated page that NAMES the row carries the row, which is what
    being rendered from it means in the only sense that matters here. Measured,
    that is not a hypothetical second member — `docs/assurance-vector.md` names
    67 of these rows because `evidence_gate.py` renders its outstanding list from
    `platform_gate.entries`, and `docs/assurance-bounds.md` names three. Reading
    the page rather than the generator's source is deliberate: which pages a
    script writes is a declaration ([`PROSE_PAGE`] says what that costs), while
    which pages carry this row is a fact about the bytes.
    """
    path = pathlib.Path(str(rel))
    if path in (ARTIFACT, REGISTRY):
        return True
    if not str(rel).lower().endswith(PROSE_PAGE) or str(rel) not in generated:
        return False
    return name in (root / path).read_text(errors="replace")


def check_evidence(root, name, entry, findings, generated, tree):
    """A status other than `pending` owes artifacts, and a board owes a stepping.

    `generated` and `tree` have no default on purpose: a defaulted `{}` reads
    every page as hand-written, which is the safe direction, but a defaulted
    `None` treated as "skip" would let a caller switch the rule off by forgetting
    it — and an empty `tree` reads every artifact as absent, which is loud.
    """
    status = entry.get("status")
    evidence = entry.get("evidence", [])
    evidence = evidence if isinstance(evidence, list) else [evidence]
    board = str(entry.get("board_revision", "")).strip()
    # Whatever the class. Gating this on HARDWARE_CLASSES was the first version,
    # and the review put "a red Pico 2 I had lying around" in an `input` row.
    if board and not names_a_stepping(board):
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
            if not in_tree(rel, tree):
                findings.append(
                    f"{name}: evidence {rel!r} is not in the tree — git's own"
                    " listing, which has no directory in it and folds no case"
                )
            elif hand_written(root, rel, generated):
                findings.append(
                    f"{name}: evidence {rel!r} is a hand-written page — a page"
                    " of prose restates the claim rather than settling it, and"
                    " `discharge` is the field this registry already keeps for"
                    " the restatement"
                )
            elif circular(root, name, rel, generated):
                findings.append(
                    f"{name}: evidence {rel!r} carries this row rather than"
                    f" settling it — {REGISTRY} holds the row, {ARTIFACT} is"
                    " rendered from that and emits its `discharge` verbatim,"
                    " and a generated page that names the row is rendered from"
                    " it too, so the claim and its evidence are one sentence"
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


#: `assurance/board/<ID>.toml`: the raw record a hardware measurement leaves
#: behind, and the reason it is a FILE rather than three more sentences in the
#: registry. Stage 2 п.9 asks for the board, the stepping, the boot
#: configuration, the firmware hash, the cut method, the first-boot capture and
#: BOTH values -- and the split below is what makes the file worth writing before
#: the run: the PLAN half is knowable in advance and the RESULT half is not, so
#: `expected` is pinned where it cannot be back-filled from what the board did.
#:
#: WHO OWES ONE is `discharge_owner == "maintainer"` and nothing else. Keying it
#: on [`HARDWARE_CLASSES`] was the first version and the review refused it with
#: this module's own words: the `CLASSES` comment above already records that the
#: class "is deliberately NOT what decides whether a row is a board result",
#: because a `tool-fidelity` row whose route reads "a board recording of the same
#: session" is a board result. Measured on the first version: 9 rows owed a
#: record while [`render`] told the reader 12 routes end at a board, and renaming
#: one row's class to `toolchain` deleted its obligation. Both numbers come from
#: the same expression now.
BOARD_PLAN_FIELDS = ("method", "boot_config", "expected")
BOARD_RESULT_FIELDS = ("board", "stepping", "firmware_sha256",
                       "first_boot_capture", "actual")
#: Read like any other field -- `note` had no rule at all in the first version,
#: and a review put "Ran it, RP2350 A2, sha 0xdeadbeef, PASSED" in it on a
#: `planned` record at exit 0.
BOARD_OPTIONAL_FIELDS = ("note",)
BOARD_KEYED_FIELDS = ("assumption", "outcome")
BOARD_OUTCOMES = {"planned", "pass", "fail", "inconclusive"}

#: Which registry status each outcome may sit under, in BOTH directions. The
#: reverse direction is the one that has actually gone wrong here: a run that was
#: taken and whose status never moved reads, from the registry alone, exactly
#: like a run nobody took -- PLAT-MEM-001 is that shape today, and its record
#: says so rather than promoting itself.
OUTCOME_STATUS = {"pass": "discharged", "fail": "refuted"}

BOARD_SHA = re.compile(r"[0-9a-f]{64}")


#: Below this the obligation lost a row rather than discharging one. Four of the
#: twelve `covers` nothing and are `depends_on` by nothing, so a review deleted
#: each of them WITH its record and the gate stayed green — the derivations do not
#: produce a candidate for "the timer is monotonic", and nothing else anchored
#: them. A floor is the smallest thing that makes the deletion a diff; what would
#: make it a derivation is stage 10's inventory, which is not this file's.
BOARD_ROW_FLOOR = 12


def board_rows(ids):
    """The rows whose route ends at a board: `discharge_owner == "maintainer"`.

    One expression, called by both the obligation and the generated page, so the
    two cannot print different numbers about the same question.
    """
    return {n for n, e in ids.items() if e.get("discharge_owner") == "maintainer"}


def _text(record, key):
    """A field's value, or None if it is not a string at all.

    `str(record.get(key, ""))` was the first version and `str([])` is `"[]"`,
    which is not empty -- so `expected = []`, `expected = 42` and
    `expected = false` all satisfied "the half that must be written before the
    board is powered". Measured, all three at exit 0.
    """
    value = record.get(key)
    return value.strip() if isinstance(value, str) else None


def check_board_records(root, ids, findings, floor=None):
    """Every maintainer-owned row has a record, and it is complete FOR ITS OUTCOME.

    Not complete in general: a planned record must carry the plan half and must
    NOT carry the result half, because a result field filled before the run is a
    value nothing measured. And a stepping may appear only in `stepping` -- the
    review smuggled a whole board result through `boot_config` and `note` while
    every rule about result fields read `""`.
    """
    owed = board_rows(ids)
    floor = BOARD_ROW_FLOOR if floor is None else floor
    if len(owed) < floor:
        findings.append(
            f"{len(owed)} maintainer-owned row(s), below the floor of"
            f" {floor} — a row deleted with its record takes its"
            " obligation with it, and no derivation produces these candidates"
        )
    seen = set()
    for path in sorted((root / BOARD_EVIDENCE).glob("*.toml")):
        rel = path.relative_to(root)
        try:
            record = _toml(path)
        except (OSError, tomllib.TOMLDecodeError) as error:
            findings.append(f"{rel}: {error}")
            continue
        name = _text(record, "assumption") or ""
        if path.stem != name:
            findings.append(
                f"{rel}: names assumption {name!r} — the file is addressed by its"
                " row and a record filed under another name is read for neither"
            )
            continue
        seen.add(name)
        if name not in ids:
            findings.append(f"{rel}: {name} is not an entry of {REGISTRY}")
            continue
        allowed = set(
            BOARD_PLAN_FIELDS + BOARD_RESULT_FIELDS
            + BOARD_OPTIONAL_FIELDS + BOARD_KEYED_FIELDS
        )
        for key in sorted(set(record) - allowed):
            findings.append(f"{rel}: `{key}` is not a field of a board record")
        for key in sorted(set(record) & allowed):
            if _text(record, key) is None:
                findings.append(
                    f"{rel}: `{key}` is {type(record[key]).__name__} and not text —"
                    " a field read through `str()` is satisfied by an empty list"
                )
        outcome = _text(record, "outcome")
        if outcome not in BOARD_OUTCOMES:
            findings.append(
                f"{rel}: outcome {outcome!r} is not one of {sorted(BOARD_OUTCOMES)}"
            )
            continue
        for key in BOARD_PLAN_FIELDS:
            if not _text(record, key):
                findings.append(
                    f"{rel}: no `{key}` — the half of the record that is knowable"
                    " before the board is powered is the half that must be written"
                    " before it is"
                )
        # A stepping is a RESULT, so it may live in one field and no other. This
        # is the rule that makes the plan/result split about substance rather
        # than about which key a sentence was typed under.
        for key in sorted(set(record) & allowed - {"stepping"}):
            value = _text(record, key) or ""
            if BOARD_REVISION.search(value):
                findings.append(
                    f"{rel}: `{key}` names a stepping — a board revision belongs"
                    " in `stepping`, where the outcome rules can see it, and"
                    " nowhere else"
                )
        filled = [k for k in BOARD_RESULT_FIELDS if _text(record, k)]
        if outcome == "planned":
            for key in filled:
                findings.append(
                    f"{rel}: outcome 'planned' with `{key}` filled — a result"
                    " field on a run that has not happened is a value nothing"
                    " measured"
                )
        else:
            for key in BOARD_RESULT_FIELDS:
                if key not in filled:
                    findings.append(f"{rel}: outcome {outcome!r} with no `{key}`")
            if "stepping" in filled and not names_a_stepping(_text(record, "stepping")):
                findings.append(
                    f"{rel}: stepping {record.get('stepping')!r} names no RP2350"
                    " stepping"
                )
            if not BOARD_SHA.fullmatch(_text(record, "firmware_sha256") or ""):
                findings.append(
                    f"{rel}: firmware_sha256 is not a sha256 — the image a board"
                    " result is about is the one field that cannot be recovered"
                    " later, and PLAT-MEM-001 is the row that lost it. Whole"
                    " value: a hash INSIDE a sentence is a sentence"
                )
            capture = _text(record, "first_boot_capture") or ""
            if capture and (not (root / capture).is_file() or capture == str(rel)):
                findings.append(
                    f"{rel}: first_boot_capture {capture!r} is not a file in the"
                    " tree beside this record — a record that is its own evidence"
                    " is the `met by README.md` rule one layer in"
                )
            check_expected_predates(root, rel, record, findings)
        want = OUTCOME_STATUS.get(outcome)
        status = ids[name].get("status")
        if want and status != want:
            findings.append(
                f"{rel}: outcome {outcome!r} under a {status!r} row — {REGISTRY}"
                f" must read {want!r} or the measurement was taken and nothing moved"
            )
        if not want and status in ("discharged", "refuted"):
            findings.append(
                f"{rel}: outcome {outcome!r} under a {status!r} row — the status"
                " moved on a record that does not carry the run behind it"
            )
    for name in sorted(owed - seen):
        findings.append(
            f"{name}: maintainer-owned {ids[name].get('class')} row with no"
            f" {BOARD_EVIDENCE}{name}.toml — the expected value has to be on"
            " record before the board is read, not after"
        )


def board_outcome(root, name):
    """One record's outcome for the generated page, or why it has none.

    Reported rather than counted: `render` printed the obligation and not what
    the records say, so nine `planned` files and nine PASSes read the same on the
    page the reader is pointed at.
    """
    path = root / BOARD_EVIDENCE / f"{name}.toml"
    if not path.is_file():
        return "**no record**"
    try:
        return str(_toml(path).get("outcome", "")).strip() or "**no outcome**"
    except (OSError, tomllib.TOMLDecodeError):
        return "**unreadable**"


def check_expected_predates(root, rel, record, findings):
    """`expected` was committed BEFORE the run, in a version that had no result.

    Without this the whole plan/result split is a convention: one commit can
    create the record with `expected` and `actual` together, `expected` written
    to match what the board did. Read out of git rather than asserted, because
    the tree cannot tell the two orders apart and history can.
    """
    done = subprocess.run(
        ["git", "-C", str(root), "log", "--format=%H", "--", str(rel)],
        capture_output=True, text=True,
    )
    if done.returncode != 0:
        findings.append(f"{rel}: git log exited {done.returncode}")
        return
    want = _text(record, "expected")
    for commit in done.stdout.split():
        blob = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{rel}"],
            capture_output=True, text=True,
        )
        if blob.returncode != 0:
            continue
        try:
            older = tomllib.loads(blob.stdout)
        except tomllib.TOMLDecodeError:
            continue
        if _text(older, "outcome") == "planned" and _text(older, "expected") == want:
            return
    findings.append(
        f"{rel}: no committed version of this record carries this `expected`"
        " with outcome 'planned' — a result whose expectation was written in the"
        " same commit is an expectation written after the fact"
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


def audit(root, board_floor=None):
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

    # Once, not per entry: one opens every `scripts/*_gate.py`, the other shells
    # out to git.
    generated = claims_gate.generated_pages(root)
    tree = set(gate_lines.tree_files(root))

    owner = {}
    for name, entry in sorted(registered.items()):
        check_shape(name, entry, findings)
        check_evidence(root, name, entry, findings, generated, tree)
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
    check_board_records(root, registered, findings, board_floor)

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
    board = sorted(board_rows(dict(rows)))
    out = [
        "<!-- SPDX-License-Identifier: AGPL-3.0-only -->",
        "<!-- Copyright (C) 2026 RS-Key contributors -->",
        f"<!-- {GENERATED_BY} — do not edit by hand -->",
        "",
        "# Platform assumptions",
        "",
        claims_gate.DISCLAIMER_PARAGRAPH,
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
        f"Each of those {len(board)} owes a RECORD as well —"
        f" `{BOARD_EVIDENCE}<id>.toml` — split into the half that is knowable"
        " before the board is powered (`method`, `boot_config`, `expected`) and"
        " the half that is not (`board`, `stepping`, `firmware_sha256`,"
        " `first_boot_capture`, `actual`). A result field on a run that has not"
        " happened is refused, and so is an `expected` first committed in the"
        " same commit as its result. What they say today:",
        "",
        "| record | outcome |",
        "|---|---|",
        *(f"| `{name}` | {board_outcome(root, name)} |" for name in board),
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


def run(root, write=False, board_floor=None):
    if write:
        (root / ARTIFACT).write_text(render(root), encoding="utf-8")
        print(f"platform-gate: wrote {ARTIFACT}")
        return 0
    findings, summary = audit(root, board_floor)
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
