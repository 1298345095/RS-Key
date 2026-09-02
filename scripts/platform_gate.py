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
leaves "an entry exists". The `M7-Q2` answer measured above IS the orphan rule, so
the amendment must disable that as well as the both-arms and reachability rules;
and the counterfactual — that gate with the two constant rules skipped for
`platform` — passes `PowerOnClearsScratch2` pinned nine ways with nothing to
falsify it. Deleting a constant from that registry instead reddens it at once, so
a second file makes the misclass a red row rather than a spelling.

The classes differ in how they are DISCHARGED, which is the other half: a model
constant is discharged by a TLC run, an entry here by a board measurement, a
vendor erratum, a source audit or an accepted risk with an owner. Nothing here
can be discharged by anything this repository runs, and **only a small minority
of entries is discharged at all**. The count is DERIVED — [`run`] prints it on a
GREEN literal run and [`render`] opens the generated page with it — because the
typed copy that stood here read `two of thirty-three` against a registry that had
grown past sixty, and no rule holds a number a docstring states. Measured, the
"prints it on every run" this sentence claimed was false in two directions and
[`main`] was the wrong function: `--write` returns before the audit, and a red run
prints on stderr. The page is what a reader who never runs the gate sees.

Eleven rules, and the first is the one that earns the file:

* **candidates are DERIVED, and every one is claimed.** Five derivations, each
  floored where its source exists and it found nothing:
  `slice:` the assumption ids the closed slice's bundle and the design pages
  carry — ten of them, and `docs/authorization-slice.md` measured **zero
  registered** before this file; `model:` every constant of the first registry,
  because a model assumption's own discharge is always a fact about the world;
  `board-only:` the suites `tests/emu.py` refuses by name that
  `scripts/usbip-guest.sh` does not run either — no runner in this tree can pass
  them, so each is a pending board obligation; `unsafe:` every `unsafe` SITE in
  first-party Rust, which is stage 10's "firmware unsafe invariant" half;
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
  in the tree; a silicon-class discharge needs the stepping it was taken on, a
  stepping written anywhere must be real whatever the class, and one carrying a
  stepping owes a raw artifact under `assurance/board/` — a rule met by any file
  that merely exists is met by `README.md`, which is how the review reached the
  hardware axis. That sentence then stood over that axis ALONE for as long as it
  was written down: on every other row `evidence = ["README.md"]` was exit 0,
  measured, and `PLAT-STORE-003`'s discharge records it. [`PROSE_PAGE`] is that
  axis's half and weaker: the comment there says which attacks it does not stop.
* **a maintainer-owned row owes a validated RECORD.** `assurance/board/<id>.toml`,
  plan half refused empty, result half refused while `planned`, `expected` older
  in git than it and `planned` there, an outcome the status must match BOTH ways.
* **links resolve.** `supports` names registry properties, `depends_on` and
  `refines` name entries here, `discharges` names constants of the first
  registry — and an entry covering `model:X` must discharge `X`, so the two
  registries cannot drift into two answers about the same constant.
* **a cell stays a cell.** A line break in `statement` or `discharge` takes Owner
  and Supports off the published row; a `<` publishes raw HTML or ends the build.
* **a settled result is DATED.** A full-sha `evidence_commit`, read against the
  row's `evidence` and the paths its own `revalidated_by` names; stale is a page.
* **an accepted risk says WHERE it is published.** `out_of_scope_by` resolves to a
  `docs/limitations.md` section that names the row, and that page's ids resolve back.
* **the page is generated.** `docs/platform-assumptions.md` is written from the
  entries and byte-diffed, so a status cannot move without the diff that says so.
* **the unsafe page is held to the tree.** AGENTS.md requires `docs/unsafe.md`
  updated for every new site and nothing checked it: measured, that page's own
  `Runtime sites:` read 21 over a tree carrying 22, and the two `link_section`
  attributes in `rsk-rsa` were on no line of it. So the count is derived and
  compared, and every file carrying a site must be NAMED there
  ([`check_unsafe_page`]) — which is not a claim that the JUSTIFICATIONS are
  right, only that the enumeration has the same members as the tree.

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
#: Optional because each is answerable ONCE, by the status that earns it: a trigger,
#: a date or a published risk on a row with none is a placeholder — 17 of the first.
OPTIONAL = set(LINKS) | {"evidence", "board_revision", "revalidated_by", "evidence_commit", "out_of_scope_by"}

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

#: A Rust identifier, and the run of `#[…]` attributes an item may wear before
#: its own head. Both read the LEXED source, so neither can be written by a
#: comment or by the inside of a string.
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ATTR_RUN = re.compile(r"\s*#!?\[")

#: How many words of a site's own code name it. Six is measured and not chosen:
#: at five the two `critical_section::with(|_| unsafe { … })` bodies in
#: `rsk-wipe` agree — both open `connect_internal_flash`, `flash_exit_xip` — and
#: separate on the sixth (`flash_range_erase` against `flash_range_program`).
#: Fewer words collide, more words make an edit three statements away rename the
#: site. Collisions are not an error: [`site_keys`] suffixes them, so the rule
#: degrades to an ordinal over the duplicates alone rather than over the file.
SITE_WORDS = 6

#: A site is in a BUILD SCRIPT (host-side, never in the image), or it is a
#: DECLARATION the compiler cannot check rather than an operation — the two
#: things `docs/unsafe.md` counts apart from its runtime sites, and so the two
#: [`runtime_sites`] takes out before comparing with that page's own number.
BUILD_SCRIPT = "build.rs"
DECLARATION_KINDS = frozenset({"attr", "extern"})

#: The page's own count of the sites it enumerates, as it writes it. Anchored on
#: the words rather than on a line, because the sentence is reflowed prose.
RUNTIME_SITES = re.compile(r"Runtime sites:\s*(\d+)")

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


def _matching(code, i, opener, closer):
    """The index just past the `closer` that balances the `opener` at `i`."""
    depth = 0
    while i < len(code):
        if code[i] == opener:
            depth += 1
        elif code[i] == closer:
            depth -= 1
            if not depth:
                return i + 1
        i += 1
    return len(code)


def _past_attributes(code, i):
    """Past a run of `#[…]`, so an attribute site is named by the ITEM it decorates.

    `#[inline(never)]` sits between `rsk-rsa`'s second `link_section` and the
    `fn` it places; without this the site is named `inline-never-pub-fn-step`,
    which renames it when an unrelated attribute is added beside it.
    """
    while (found := ATTR_RUN.match(code, i)) is not None:
        i = _matching(code, found.end() - 1, "[", "]")
    return i


def unsafe_sites(code):
    """(offset, kind, slug) per `unsafe` token in already-lexed Rust `code`.

    The KIND is the token that follows: `fn`, `impl`, `extern`, an `attr` for the
    2024 `#[unsafe(…)]` form, and `block` for everything else. The SLUG is the
    first [`SITE_WORDS`] words of the site's OWN code — its balanced `{ … }`, or
    up to the `;` where it has none.

    Deliberately content and not position. An ordinal — the n-th `unsafe` in the
    file — is derivable and stable-looking and is the shape this repo has already
    been bitten by: inserting a site above another renumbers every one below it,
    the candidate SET grows by one, and each surviving row keeps a key that now
    denotes a different site. That is green, and it is a row whose justification
    has silently re-pointed. A slug moves only when the site's own code moves.

    An `attr` reads past its attribute to the item, because the discriminating
    half of `#[unsafe(link_section = "…")]` is a string LITERAL and the lexer has
    already blanked it — the two in `rsk-rsa` are otherwise the same three
    characters, and would be one candidate for two placements.
    """
    for found in UNSAFE.finditer(code):
        after = found.end()
        while after < len(code) and code[after].isspace():
            after += 1
        if code[after : after + 1] == "(":
            kind = "attr"
            end = _matching(code, after, "(", ")")
            item = _past_attributes(
                code, next((i for i in range(end, len(code)) if code[i] not in ") ]\t\r\n"), end)
            )
            stop = min(
                (p for p in (code.find(c, item) for c in "{;=") if p >= 0),
                default=len(code),
            )
            span = f"{code[found.end():end]} {code[item:stop]}"
        else:
            word = WORD.match(code, after)
            kind = word.group(0) if word and word.group(0) in ("fn", "impl", "extern") else "block"
            brace, semi = code.find("{", found.end()), code.find(";", found.end())
            end = (
                _matching(code, brace, "{", "}")
                if brace >= 0 and (semi < 0 or brace < semi)
                else (semi + 1 if semi >= 0 else len(code))
            )
            span = code[found.end() : end]
        words = [w.lower() for w in WORD.findall(span) if w != "unsafe"]
        if words and words[0] == kind:
            words = words[1:]  # `extern:extern-…` says the same thing twice
        yield found.start(), kind, "-".join(words[:SITE_WORDS]) or "anonymous"


def site_keys(code):
    """`<kind>:<slug>` per site, in source order, duplicates suffixed `~2`, `~3`.

    Two sites that agree on kind and on their first six words are the same
    construct written twice, so the ordinal that separates them moves only when
    another COPY is inserted between them — not when any site at all is.
    """
    seen = {}
    for _offset, kind, slug in unsafe_sites(code):
        key = f"{kind}:{slug}"
        seen[key] = seen.get(key, 0) + 1
        yield key if seen[key] == 1 else f"{key}~{seen[key]}"


def unsafe_files(root):
    """rel -> its lexed code, for every first-party `.rs` carrying the token."""
    out = {}
    for rel in sorted(gate_lines.tree_files(root)):
        if rel.suffix != ".rs" or str(rel).startswith(UNSAFE_EXCLUDED):
            continue
        code = gate_lines.rust_code((root / rel).read_text(errors="replace"))
        if UNSAFE.search(code):
            out[rel] = code
    return out


def unsafe_candidates(root):
    """Every `unsafe` SITE of first-party Rust, keyed by its own code.

    Per FILE was the first version and it is the finding this replaced: seven
    candidates over thirty-one sites, all seven claimed by one entry, so
    `docs/unsafe.md`'s twenty-one numbered justifications stood behind a single
    registry row and a new `unsafe` in a file that already had one was **exit
    0** — the both-ways rule cannot see a candidate that did not change.
    """
    return {
        f"{rel}#{key}": f"an `unsafe` site in {rel}, justified in {UNSAFE_PAGE}"
        for rel, code in unsafe_files(root).items()
        for key in site_keys(code)
    }


def unsafe_keys(found):
    """The `unsafe:` members of a candidate map, with the namespace taken off.

    Selected out of the whole map rather than derived a second time: a second
    walk of the tree is a second answer to which sites exist, and the page rules
    below have to be about the same set the both-ways rule claims.
    """
    return sorted(key.split(":", 1)[1] for key in found if key.startswith("unsafe:"))


def runtime_sites(found):
    """The candidate keys `docs/unsafe.md` counts as RUNTIME sites.

    Its own partition, derived rather than transcribed: that page keeps build
    scripts and the edition-2024 declarations in a section apart from the
    numbered ones, so the number to compare with is the sites that are neither.
    """
    return [
        key
        for key in unsafe_keys(found)
        if pathlib.Path(key.split("#", 1)[0]).name != BUILD_SCRIPT
        and key.split("#", 1)[1].split(":", 1)[0] not in DECLARATION_KINDS
    ]


def check_unsafe_page(root, found, findings):
    """`docs/unsafe.md` has the same members as the tree, both ways.

    AGENTS.md makes updating that page a rule for every new site and no gate read
    it, so the drift went the way an unheld number always does: `Runtime sites:`
    said 21 while the tree carried 22 — the third sieve access, added with the
    section's own prose ("three call sites") and not with its heading — and the
    two `link_section` attributes in `rsk-rsa` were named nowhere on it.

    What this does NOT check is whether a justification is right, or still about
    the site it sits under; that is a reading, and the registry rows are where
    it is written down. It checks the two things a count and a file list can:
    that the page's own number is the tree's, and that no file carrying a site
    is missing from the page entirely.
    """
    page = root / UNSAFE_PAGE
    text = page.read_text(errors="replace") if page.is_file() else ""
    stated = RUNTIME_SITES.findall(text)
    want = len(runtime_sites(found))
    if len(stated) != 1:
        findings.append(
            f"{UNSAFE_PAGE}: {len(stated)} `Runtime sites: <n>` statements — the"
            " page's own count of what it enumerates is what holds it to the"
            f" tree, and the tree has {want}"
        )
    elif int(stated[0]) != want:
        findings.append(
            f"{UNSAFE_PAGE}: says `Runtime sites: {stated[0]}` and the tree has"
            f" {want} — a site added without its entry leaves the page's own"
            " number as the only thing that says so, which is why it is derived"
        )
    for rel in sorted({key.split("#", 1)[0] for key in unsafe_keys(found)}):
        if rel not in text:
            findings.append(
                f"{UNSAFE_PAGE}: names no site in {rel}, which carries one —"
                " AGENTS.md makes this page the enumeration, and a file absent"
                " from it is a justification nobody wrote"
            )


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
        # DECORATIVE today: 0 of 74 rows carry a `board_revision`, so cutting this
        # arm leaves the summary byte-identical; a discharge carrying one wakes it.
        if board and not any(str(rel).startswith(BOARD_EVIDENCE) for rel in evidence):
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


#: The page that publishes what this project does NOT defend against, and the one
#: an `accepted-risk` row has to point INTO. `scripts/test_threat_gate.py` has a
#: case recording it as cited by nothing yet, and that was literal: before this
#: rule, ZERO rows of any `assurance/*.toml` named it, so stage 9 п.5 and stage 10
#: п.5 — "the accepted risk is published" — were both claims about a page no
#: register referenced and no gate could check.
LIMITATIONS = pathlib.Path("docs/limitations.md")

#: An `out_of_scope_by` value: that page, then a RENDERED anchor. The fragment is
#: an mdBook id and NOT a registry id, which is the one place this parts company
#: with `threat_gate.REF` — `docs/threat-model.md` carries no anchors and is
#: addressed by clause id, while this page is addressed by the heading a reader
#: lands on. Narrow on purpose: `#Cryptography`, `./docs/limitations.md#…`, a bare
#: path and a fragment with a space each fall through every rule below while
#: LOOKING published, which is the spelling `threat_gate.check_sources` refuses in
#: the same words.
OUT_OF_SCOPE_REF = re.compile(rf"^{re.escape(str(LIMITATIONS))}#([a-z0-9_-]+)$")

#: A markdown heading of that page, and the fenced run to skip over it — the two
#: shapes `threat_gate.clause_units` reads `docs/threat-model.md` with, for its
#: reason: a `#` inside a code sample is not a section, and a section that is not
#: there is an anchor that sends a reader nowhere.
PAGE_HEADING = re.compile(r"^(#{1,6})\s+(\S.*?)\s*$")
PAGE_FENCE = re.compile(r"^\s*(?:```|~~~)")

#: This registry's ids as PROSE writes them, which is the other direction of the
#: same citation. Three are on the page today.
PAGE_ENTRY_ID = re.compile(r"\bPLAT-[A-Z]+-\d{3}\b")


def normalize_id(text):
    """mdBook's own `normalize_id`, which is what decides the anchor.

    Not reasoned about: measured against `book/limitations.html` out of a real
    `scripts/docs.sh build`, where `## Backup & migration` is `backup--migration`
    and `## Hardware / physical` is `hardware--physical`. TWO dashes, because the
    dropped character leaves the space on either side of it — a slugger that
    collapses the run links to an anchor the page does not have, and `lychee
    --offline` does not check fragments, so nothing else in this tree would say so.
    """
    out = []
    for char in str(text):
        if char.isalnum() or char in "_-":
            out.append(char.lower() if "A" <= char <= "Z" else char)
        elif char.isspace():
            out.append("-")
    return "".join(out)


def limitations_page(root):
    """(anchor -> heading text, anchor -> the ids that section names).

    One pass for both, because they are the two directions of one citation: a row
    pins a section, and the section names the row. `setdefault` on a repeated
    anchor keeps the FIRST, which is the id mdBook leaves unsuffixed.
    """
    path = root / LIMITATIONS
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    headings, mentions, anchor, fenced = {}, {}, "", False
    for line in text.splitlines():
        if PAGE_FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        found = PAGE_HEADING.match(line)
        if found:
            anchor = normalize_id(found.group(2))
            headings.setdefault(anchor, found.group(2))
            mentions.setdefault(anchor, set())
            continue
        for name in PAGE_ENTRY_ID.findall(line):
            mentions.setdefault(anchor, set()).add(name)
    return headings, mentions


def check_out_of_scope(name, entry, findings, headings, mentions):
    """An `accepted-risk` row says WHERE its risk is published, and the page agrees.

    The obligation is DERIVED from the page rather than declared here, the way
    `check_bundles` derives `registered`: a row is owed a pin when the page
    already names it. That is 2 of the 4 accepted-risk rows and it is deliberately
    not 4 — `PLAT-MODEL-008` and `PLAT-MODEL-014` are model OVER-APPROXIMATIONS
    whose discharge route reads "nothing to run", and this page opens by saying it
    covers feature and hardware gaps. Minting an anchor for them would publish a
    proof-scope note as a user-facing limitation, which is a page saying something
    it does not mean; the honest reading is that `accepted-risk` is carrying two
    different things and splitting it is the maintainer's call.
    """
    published = {n for ids in mentions.values() for n in ids}
    ref = str(entry.get("out_of_scope_by", "")).strip()
    if entry.get("status") == "accepted-risk":
        if not ref and name in published:
            findings.append(
                f"{name}: {LIMITATIONS} publishes this row and it carries no"
                " `out_of_scope_by` — a risk the page names and the registry does"
                " not point back at is a citation with one end, and which section"
                " publishes it is then a thing only a reader can find"
            )
    elif ref:
        findings.append(
            f"{name}: status {entry.get('status')!r} carries `out_of_scope_by` —"
            " the field says a risk was ACCEPTED and published, and a row that has"
            " not accepted one is pointing at a section about something else"
        )
    if not ref:
        return
    found = OUT_OF_SCOPE_REF.match(ref)
    if not found:
        findings.append(
            f"{name}: out_of_scope_by {ref!r} is not `{LIMITATIONS}#<anchor>` —"
            " the anchor is the mdBook id of a heading, lower-cased with every"
            " dropped character leaving its spaces behind, and any other spelling"
            " resolves to nothing while reading as published"
        )
        return
    anchor = found.group(1)
    if anchor not in headings or name not in mentions.get(anchor, set()):
        why = (
            "is no section of that page"
            if anchor not in headings
            else f"is {headings[anchor]!r}, which does not name this row"
        )
        findings.append(
            f"{name}: out_of_scope_by anchor `#{anchor}` {why} — the pin and the"
            " page have to agree about WHICH section publishes the risk, or the"
            " row points at a heading that stopped being about it"
        )


def check_published_ids(ids, findings, mentions):
    """Every `PLAT-…` the page writes is an entry of this registry.

    The reverse of the rule above and the cheaper half: `docs/limitations.md` sends
    a reader to three of these ids in prose, and a rename or a deletion here would
    leave the page authoritative and pointing at nothing. Not the other reverse —
    holding every SECTION to an accepted-risk row was measured and refused: the
    page has 5, and at most 2 could ever be claimed, because the rest publish
    feature gaps (brainpool, X448, the USB identity) that are not platform
    assumptions at all. A rule red by construction over content it has no business
    governing is the decoration this file refuses everywhere else.
    """
    for anchor, names in sorted(mentions.items()):
        for name in sorted(names):
            if name not in ids:
                findings.append(
                    f"{LIMITATIONS}#{anchor} names {name}, which is no entry of"
                    f" {REGISTRY} — the page reads as authoritative about a row"
                    " that was renamed or deleted out from under it"
                )


#: The suffixes a path can have in this tree, used to read the in-tree paths a
#: row's own `revalidated_by` names. Filtered through `in_tree` afterwards, which
#: is what makes it a derivation rather than a guess: `formal/*.cfg` and
#: `git grep -n '…' -- crates` both survive this pattern and neither is a file, so
#: git's own listing is what decides.
PROSE_PATH = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:md|toml|tla|cfg|rs|py|sh|txt|log|json|nix|lock)"
)


def revalidation_inputs(root, entry, tree):
    """The files a settled row's claim is ABOUT: its `evidence`, plus every
    in-tree path its own `revalidated_by` names.

    The union and not `evidence` alone, and the reason is measured rather than
    symmetric with `evidence_gate.evidence_inputs`. `PLAT-CRED-004`'s trigger
    sentence names an emit in `formal/gen-configs.sh` that its whole discharge
    rests on, and that file is in no `evidence` list: read from `evidence`
    only, that row is behind ONE input; read from the union it is behind two, and
    the second is the file the row itself says would unsettle it. Nothing is added
    for the other two rows, so this is one measured input on one of three and not
    a wider net for its own sake.

    Not a second hand-written list either — `revalidated_by` is already there and
    already required of a settled row; what is new is reading it instead of only
    printing it.
    """
    evidence = entry.get("evidence", [])
    evidence = evidence if isinstance(evidence, list) else [evidence]
    prose = set(PROSE_PATH.findall(str(entry.get("revalidated_by", ""))))
    return sorted({str(rel) for rel in evidence} | {p for p in prose if in_tree(p, tree)})


def last_commit(root, rel):
    """The commit that last touched `rel`, or `""` — never a silent success.

    A git failure returns `""` and `freshness` reads that as NOT covered, which is
    the direction `evidence_gate.git`'s docstring names: a guard that reads a git
    failure as "nothing changed" reports fresh evidence over a history it could
    not open.
    """
    done = subprocess.run(
        ["git", "-C", str(root), "log", "-1", "--format=%H", "--", str(rel)],
        capture_output=True, text=True, check=False,
    )
    return done.stdout.strip() if done.returncode == 0 else ""


def freshness(root, commit, inputs, memo=None):
    """(verdict, the inputs the recorded commit does not cover).

    `evidence_gate.freshness`'s rule, asked of this registry's rows: an input is
    covered when the commit that last touched it IS, or is an ancestor of, the
    commit the row recorded. Pure committed history, so writing the page and then
    committing it cannot change the answer between the two — and so the hole is
    the same one that page names: an uncommitted edit to an input is invisible
    until it lands.

    `memo` is [`settled_freshness`]'s per-run cache of the `git log` half, and it
    is per RUN and not a module global: two rows here share
    `formal/RSKeySecurityState.tla`, and a cache that outlived one call would
    answer from a history a fixture has since committed to.
    """
    known = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True, text=True, check=False,
    )
    if known.returncode:
        return "unknown-commit", []
    memo = {} if memo is None else memo
    behind = []
    for rel in inputs:
        if rel not in memo:
            memo[rel] = last_commit(root, rel)
        last = memo[rel]
        if not last:
            behind.append(rel)  # never committed, or a history that would not open
            continue
        # A commit is its own ancestor, so this is the same answer for one less
        # process — and it is the common one, because the commit a result was
        # taken at is usually the one that wrote the artifacts it rests on.
        if last == commit:
            continue
        done = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", last, commit],
            capture_output=True, text=True, check=False,
        )
        if done.returncode:
            behind.append(rel)
    return ("fresh" if not behind else "stale"), behind


#: The statuses that owe a date. The same pair `check_evidence` already makes owe
#: `evidence` and `revalidated_by`: a result was recorded, so there is a commit it
#: was recorded AT. `accepted-risk` is not one — nothing was measured, so there is
#: no run for a date to be about, and a date there would be the decoration the
#: `elif` above already refuses in its own words.
SETTLED = ("discharged", "refuted")

#: What a date has to LOOK like: a full object name. Not `[0-9a-f]+`, because git
#: resolves an abbreviation and a REF alike — `evidence_commit = "HEAD"` passes
#: `cat-file`, dates the result at whatever is checked out, and reports every row
#: fresh forever, which is this module's "met by README.md" sentence with a
#: revision substituted. Measured: exit 0 before this line. An abbreviation is out
#: for the weaker but real reason that it stops being unique as history grows.
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def settled_freshness(root, registered, tree):
    """id -> (commit, verdict, inputs it is behind), for every dated settled row.

    Computed once by [`audit`] and handed to [`render`], because it shells out to
    git per input and both of them want the same answer.
    """
    out, memo = {}, {}
    for name, entry in sorted(registered.items()):
        commit = str(entry.get("evidence_commit", "")).strip()
        if entry.get("status") not in SETTLED or not commit:
            continue
        inputs = revalidation_inputs(root, entry, tree)
        out[name] = (commit, *freshness(root, commit, inputs, memo))
    return out


def check_freshness(name, entry, findings, vector):
    """A settled row is DATED, and only a settled row is.

    Stage 10 п.3 asks that an assumption mark its dependent claims stale, and
    `grep -c stale` over this file answered 0: the registry had `revalidated_by`,
    a sentence naming what would unsettle a row, and no machine could tell whether
    that had happened. `evidence_gate` had the machine and reads bundles, not this
    file.

    Being STALE is not a finding here, for the reason it is not one there: measured
    over the 11 bundles that record a commit, 11 are stale, so a red on staleness
    is a gate that is red as its resting state. What is a finding is a settled row
    with no date at all, and one whose date this history does not have — the two
    ways the axis stops being computable. The staleness itself lands on
    [`ARTIFACT`], where a row going stale is a diff someone has to write and read.
    """
    commit = str(entry.get("evidence_commit", "")).strip()
    if entry.get("status") in SETTLED:
        if not commit:
            findings.append(
                f"{name}: status {entry.get('status')!r} with no `evidence_commit`"
                " — a result with no date cannot go stale, so `revalidated_by`"
                " stays a sentence nothing checks and the row reads settled"
                " through the change that unsettles it"
            )
    elif commit:
        findings.append(
            f"{name}: status {entry.get('status')!r} carries an"
            " `evidence_commit` — a date on a result nobody took, which is the"
            " same decoration as evidence under an undischarged row"
        )
    if commit and not COMMIT_SHA.fullmatch(commit):
        findings.append(
            f"{name}: `evidence_commit` {commit[:20]!r} is not a full commit sha"
            " — git resolves a ref and an abbreviation alike, so a date written"
            " `HEAD` moves with the checkout and reports the row fresh forever"
        )
    if commit and vector and vector[1] == "unknown-commit":
        findings.append(
            f"{name}: `evidence_commit` {commit[:12]} is not a commit this history"
            " has — an evidence date nothing can check"
        )


def inherits(name, registered):
    """What goes stale with `name`: the properties it supports, then the rows that
    rest on it. Stage 10 п.3's "dependent claims", derived from the links the
    registry already carries rather than from a second list of them.
    """
    onward = sorted(
        other
        for other, entry in registered.items()
        for kind in ("depends_on", "refines")
        if name in entry.get(kind, [])
    )
    return sorted(registered[name].get("supports", [])) + onward


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
    headings, mentions = limitations_page(root)
    dated = settled_freshness(root, registered, tree)

    owner = {}
    for name, entry in sorted(registered.items()):
        check_shape(name, entry, findings)
        check_cells(name, entry, findings)
        check_evidence(root, name, entry, findings, generated, tree)
        check_freshness(name, entry, findings, dated.get(name))
        check_out_of_scope(name, entry, findings, headings, mentions)
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
    check_published_ids(registered, findings, mentions)
    check_unsafe_page(root, found, findings)

    try:
        want = render(root, registered, dated)
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


#: The two fields of a row that reach the page as free prose, and so the two an
#: escape has an arm for. `class`, `status`, the id, `supports`, the board
#: outcome and the graph targets are closed vocabularies or ids [`check_shape`]
#: and [`check_links`] already refuse — and so is `discharge_owner`, which is why
#: [`render`] passes it through: a clause a rule above it makes unreachable is
#: decoration, and this file's own commit said so while wrapping it anyway.
#: `failure_direction` is hand-written prose and is NOT here, because no
#: generator in this tree renders it: `git grep failure_direction -- scripts/`
#: answers three hits in this file and none outside a test.
RENDERED_PROSE = ("statement", "discharge")

#: What such a cell may not carry. A `|` is ESCAPED ([`cell`]); these cannot be,
#: and every one is measured through mdBook rather than reasoned about:
#:
#: * `\n` — a line break ends the row exactly as a bare `|` did. Measured with
#:   one in `PLAT-MODEL-002`'s discharge: the published row rendered four cells,
#:   its Owner and its whole `supports` list came off the page, and the gate,
#:   this suite and `mdbook build` were all **exit 0**. That is the pipe defect
#:   again, past the fix for the pipe defect.
#: * `\r` — the same break, plus a red that never converges: `read_text` folds it
#:   back to `\n`, so the byte-diff finds the page differs from the generator
#:   FOREVER and asks for a `--write` that cannot settle it. Measured: exit 1
#:   after `--write`, with a message about committing the result.
#: * `<` — raw HTML. `</td><td>` exits `mdbook build` **101** ("pop too far"), so
#:   the docs row dies rather than reddening with a name; `<script>alert(1)</script>`,
#:   `<br>` and `<!-- -->` all reached the built page as markup, at exit 0.
#:
#: NOT `>`: seven rows write one (`->`, `a > b`) and GFM prints `&gt;`. NOT `&`,
#: which three rows write. Nor the fullwidth `｜`, a tab, a leading `#`, a
#: trailing `\`, or a `|` inside a code span — all five measured at exit 0, seven
#: cells, no markup. A clause for a character no row carries and no arm can drive
#: is the shape this file refuses everywhere else.
CELL_REFUSED = "\r\n<"


def check_cells(name, entry, findings):
    """The named half of [`cell`]'s refusal, per row and per field.

    Two guards over one rule, and they are not the same guard: this one names the
    entry and the field, which is what a contributor needs; [`cell`] is what
    stops the page being WRITTEN, and it is the only half `evidence_gate.py` has
    — that gate renders the same `statement` into `docs/assurance-vector.md` and
    never calls [`check_shape`].
    """
    for key in RENDERED_PROSE:
        carried = sorted({c for c in str(entry.get(key, "")) if c in CELL_REFUSED})
        if carried:
            findings.append(
                f"{name}: `{key}` carries {carried} — {ARTIFACT} interpolates it"
                " into a `|`-delimited row, where a line break takes Owner and"
                " Supports off the page and `<` publishes raw HTML into it or"
                " ends the build"
            )


def cell(text):
    r"""A markdown table cell. An unescaped `|` in prose ends the row otherwise.

    `PLAT-SOURCE-002`'s discharge writes `r.map(|()| tok)`, which wrote NINE
    cells into this table's seven columns: GFM DROPS the excess, so that row
    published a fragment of prose where its owner belongs and no `supports` at
    all. Measured through mdBook, the renderer the page is read in.

    Escaping the BACKSLASH as well was measured and is a REGRESSION: inside a
    table `\|` is the one sequence a code span honours, so `\in` would render
    `\\in` on the four rows that write one, while `\|` -> `\\|` already renders
    `\|` — restoring the `git grep` alternation `PLAT-MODEL-009` means the
    reader to paste, which this page had been eating.

    [`CELL_REFUSED`] is the half no escape reaches, and it RAISES rather than
    mangling: [`audit`] catches `ValueError` off [`render`] and so does
    `evidence_gate.audit`, so both pages refuse to be generated with a named
    finding, and [`run`] refuses the `--write` rather than writing the damage.
    """
    text = str(text)
    carried = sorted({c for c in text if c in CELL_REFUSED})
    if carried:
        raise ValueError(
            f"a table cell carries {carried}, which no escape reaches — a line"
            " break ends the row as a bare `|` does and `<` opens raw HTML in a"
            f" published page. In: {text.strip()[:48]!r}"
        )
    return text.replace("|", "\\|")


def render(root, registered=None, dated=None):
    """`docs/platform-assumptions.md` as the tree makes it."""
    root = pathlib.Path(root)
    registered = entries(root, []) if registered is None else registered
    if dated is None:
        dated = settled_freshness(root, registered, set(gate_lines.tree_files(root)))
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
        " this tree can pass, every `unsafe` SITE in first-party Rust, and the"
        " semantics a crate-ledger row says its model abstracts. An unclaimed"
        " candidate reddens `scripts/platform_gate.py`; so does a claim on a"
        f" candidate that no longer exists. {len(unsafe_keys(found))} of them are"
        " `unsafe` sites, keyed by their own code rather than by a position, so"
        " that a site inserted above another cannot renumber a row onto a"
        " different one.",
        "",
        "## The registry",
        "",
        "| ID | Class | Statement | Status | Discharged by | Owner | Supports |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, entry in rows:
        supports = ", ".join(f"`{p}`" for p in entry.get("supports", [])) or "—"
        out.append(
            f"| `{name}` | `{entry.get('class')}` | {cell(entry.get('statement'))} |"
            f" **{entry.get('status')}** | {cell(entry.get('discharge'))} |"
            f" {entry.get('discharge_owner')} | {supports} |"
        )
    settled = [n for n, e in rows if e.get("status") in SETTLED]
    stale = [n for n in settled if dated.get(n, ("", "", []))[1] == "stale"]
    out += [
        "",
        "## Freshness",
        "",
        f"A settled row records the commit its result was taken at, and {len(settled)}"
        " of these do. An input is COVERED when the commit that last touched it is"
        " an ancestor of that one; a row behind any of its inputs is **stale**, and"
        " the claims resting on it inherit that. The inputs are derived, not"
        " listed: a row's `evidence`, plus every in-tree path its own"
        " `revalidated_by` names — which is how `formal/gen-configs.sh` reaches"
        " `PLAT-CRED-004`, whose whole discharge rests on an emit in that file and"
        " whose `evidence` does not mention it.",
        "",
        "Committed history only, so an uncommitted edit to an input is invisible"
        " until it lands — the same hole `docs/assurance-vector.md` names about"
        f" itself. Stale is not a red: {len(stale)} of {len(settled)} are stale"
        " right now, and a gate red in its resting state is one nobody reads. What"
        " it costs instead is this page — a row going stale is a diff.",
        "",
        "| ID | Taken at | Freshness | Behind | Claims that inherit it |",
        "|---|---|---|---|---|",
    ]
    for name in settled:
        commit, verdict, behind = dated.get(name, ("", "undated", []))
        onward = ", ".join(f"`{c}`" for c in inherits(name, registered)) or "—"
        out.append(
            f"| `{name}` | `{commit[:7] or '—'}` | **{verdict}** |"
            f" {', '.join(f'`{cell(rel)}`' for rel in behind) or '—'} | {onward} |"
        )
    headings, mentions = limitations_page(root)
    accepted = [n for n, e in rows if e.get("status") == "accepted-risk"]
    out += [
        "",
        "## Where the accepted risks are published",
        "",
        f"{len(accepted)} rows accept a risk rather than discharging it, and an"
        " accepted risk that is not published is a decision only this file knows"
        f" about. `{LIMITATIONS}` is where the project publishes them; a row the"
        " page names pins the section back, and the pin and the page must agree"
        " about which section that is.",
        "",
        "| ID | Published as |",
        "|---|---|",
    ]
    for name in accepted:
        ref = str(registered[name].get("out_of_scope_by", "")).strip()
        anchor = ref.partition("#")[2]
        out.append(
            f"| `{name}` | "
            + (f"[{cell(headings.get(anchor, anchor))}]({LIMITATIONS.name}#{anchor})"
               if ref else "**not published there**")
            + " |"
        )
    out.append(
        f"\nThe {sum(1 for n in accepted if not str(registered[n].get('out_of_scope_by', '')).strip())}"
        " unpublished rows are model OVER-APPROXIMATIONS whose discharge route"
        " reads `nothing to run`, and that page opens by saying it covers feature"
        " and hardware gaps. An anchor minted for them would publish a proof-scope"
        " note as a user-facing limitation, so the status word is what is carrying"
        " two different things here, and splitting it is a decision and not a"
        " generated table's."
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
        f"- that the list is complete. {len(FLOORS)} derivations produce it, and"
        " stage 10's inventory names eleven categories — a category with no"
        " candidate source is a category this page cannot see.",
        "- that a discharged row makes a property proved. It removes a condition;"
        " the property's own evidence is `docs/assurance-vector.md`'s.",
        "",
    ]
    return "\n".join(out)


def run(root, write=False, board_floor=None):
    if write:
        # `--write` runs no rule, so [`cell`]'s raise arrives here as the only
        # thing between a refused character and a damaged page. Named rather than
        # a traceback, and the page is left alone: nothing half-written.
        try:
            page = render(root)
        except ValueError as error:
            print(f"platform-gate: {ARTIFACT} not written — {error}", file=sys.stderr)
            return 1
        (root / ARTIFACT).write_text(page, encoding="utf-8")
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
