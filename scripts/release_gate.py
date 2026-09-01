#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The release procedure, as a manifest of exact commands and inputs.

Stage 11A work 5 asks for a release evidence manifest that records the exact
commands and the exact inputs a release runs. Measured against the tree this was
written for, what a reader could find was prose: `docs/supply-chain.md` says the
job "rebuilds all fourteen flavors with `nix build --rebuild`" and
`docs/releases.md` says "It builds every artifact reproducibly, hashes it, and
signs the manifest". Neither sentence is read by anything, both are transcribed
from a workflow file, and one of them had already rotted once in this tree's
history — the signature asset was renamed `SHA256SUMS.cosign.bundle` ->
`SHA256SUMS.sigstore.json` and every published verify command named a file that
no longer exists for releases after v0.4.10.

So the commands are DERIVED, out of the three files that decide what a release
is: `.github/workflows/release.yml` (which tag becomes a release),
`.github/workflows/release-build.yml` (every step that builds, attests, signs and
publishes) and `nix/firmware.nix` (what happens inside the sandbox, and which
flags make each flavor the image it is). Nothing about the procedure is typed
here twice.

## Recipe, not record — and the half that is open

**This manifest is a RECIPE.** It says what commands a release runs and over
which inputs. It is NOT a RECORD: it binds to no tag, no commit, no runner, and
no artifact digest, because none of those exists until a `v*` tag is pushed and
`release-build.yml` runs — which is a maintainer action, not a code edit. The
record half is written into the region as [`OPEN`], with its cost, rather than
faked with a placeholder.

That is also the reason [`stable`] exists. A generated region is byte-diffed on
every `check.sh` run, so a value that changes on every commit would leave the
region permanently dirty and the row a nuisance instead of a guard. Every value
below is a function of a file's CONTENT, so it moves when that file moves and at
no other time; the rule refuses any hex in the rendered region that names a
commit of this repository, which is what a "which revision built it" field would
have to be.

## `bit-for-bit` is not `source->binary`

The two words are one letter apart in a reader's memory and they are different
claims, so they are different [`SUBJECTS`] and the difference is checked:

* `bit-for-bit` — the same inputs produce the same output bytes. A property of
  the BUILD, established here, by the `--rebuild` step.
* `source->binary` — the emitted machine code does what the source says. A
  property of the COMPILER. **Nothing in this pipeline establishes it**, and the
  registry already says so: `assurance/platform.toml`'s `PLAT-TOOLCHAIN-001` is
  `pending` and its own discharge sentence reads "Stage 11's source-to-binary
  work. Nothing in the tree bridges MIR to the image today."

Determinism is not semantic preservation: a compiler that miscompiles the same
way twice rebuilds bit-identically. So an entry whose command is the
reproducibility rebuild and whose `subject` reads `source->binary` is exactly the
misreading this rule refuses, and it is refused twice over — once because a
`subject` is held against the shape of its own command ([`SHAPE`]), and once
because `source->binary` is not in that map's image at all, which [`frontier`]
asserts rather than assumes.

## The rules

1. **[`ENTRIES`] and the workflow's steps, both ways.** Each entry names a step
   by a substring that must match exactly ONE of them, and every step of the job
   must be claimed by exactly one entry. A roster that lists only what somebody
   remembered is correct row by row while being short, which is the failure this
   whole class of file exists to prevent.
2. **A `subject` is never the authority.** It is hand-written and held against
   the shape of the command the step actually runs ([`SHAPE`]), the way
   `assurance/toolchain.toml`'s `pin` is held against the file that pins it.
3. **[`frontier`]** — `source->binary` is not in [`SHAPE`]'s image, so no entry
   can carry it; and it is printed as open exactly while `PLAT-TOOLCHAIN-001` is
   `pending`. Discharging that row while this page still calls the gap open is a
   finding, and so is the reverse.
4. **The two flavor loops agree.** There are exactly two `for pkg in` lists —
   the build's and the reproducibility gate's — they are equal (a rebuild gate
   covering thirteen of fourteen images publishes the fourteenth unchecked),
   every name is a `mkFirmware` package of `nix/firmware.nix`, and none is a
   `no-touch` build by NAME or by the feature it compiles.
5. **A typed count is held to the list it counts.** "build the 14 reproducible
   firmware flavors" is a hand-typed number inside the procedure, and "the 14
   `.uf2` flavors" / "Fourteen firmware images" are two more on the pages a
   reader takes the number from. Each must equal the length of the loop.
6. **The caller calls this builder and nothing else.** `release.yml`'s `uses:`
   must be exactly `release-build.yml`, because that identity is what the
   published `cosign verify-blob --certificate-identity-regexp` checks and what
   makes the provenance SLSA Build L3 rather than L2 — and because a second
   called workflow is a release step this manifest never opens.
7. **[`stable`]** — see above.
8. **The published set, both ways and on both pages.** Every asset a page names
   is one this workflow writes AND one `gh release create` uploads; nothing is
   copied into `dist/` under a name this parser cannot read. [`HISTORICAL`] is
   the one carve-out: held both ways so it cannot outlive its reason, and
   refused inside a fenced block, because a dead name in prose about five
   immutable releases is history and a dead name in a command is a lie.
9. **The region is PRINTED and byte-diffed**, into `docs/supply-chain.md` beside
   the toolchain table, the way `scripts/toolchain_gate.py` owns its region
   there. A region and not an `ARTIFACT`/`GENERATED_BY` pair, for that gate's
   reason: `claims_gate.generated_pages` reads that pair to excuse a page WHOLE,
   and `docs/supply-chain.md` is prose that must stay under the claims rule.
10. **Floors.** Every rule above is satisfied by an empty roster, so the entry
    and flavor counts are floored — the loop-over-nothing shape.

## What this does NOT prove

* **That a release ran any of this.** Nothing here observes a workflow run. The
  manifest is what the tree SAYS a release does; the attestation is what a
  release says it did, and the two are only tied together once a tag exists
  ([`OPEN`]).
* **That the artifact you downloaded is the one these commands produced.** That
  is `SHA256SUMS` plus the cosign signature plus `gh attestation verify`, all
  three of which this manifest describes and none of which it performs.
* **Anything about the machine code.** See `source->binary` above.
"""

from __future__ import annotations

import fnmatch
import hashlib
import pathlib
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import claims_gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

WORKFLOW = pathlib.Path(".github/workflows/release-build.yml")
CALLER = pathlib.Path(".github/workflows/release.yml")
NIX = pathlib.Path("nix/firmware.nix")
PLATFORM = pathlib.Path("assurance/platform.toml")
PAGE = pathlib.Path("docs/supply-chain.md")

#: The pages whose asset names and flavor counts are held to the workflow. The
#: region lives on the first; the second is here because it carries the SAME
#: verify commands and is the page a downloader is sent to, so scoping the rule
#: to one page leaves the rot it exists to refuse open on the other — measured by
#: review: renaming the signature asset and repairing every mention on
#: `docs/supply-chain.md` was exit 0 with three stale mentions on `docs/releases.md`.
PAGES = (PAGE, pathlib.Path("docs/releases.md"))

#: The files whose CONTENT decides what a release is, digested into the region.
#: The table below prints the commands it reads out of them; a digest also covers
#: the parts it does not print — a `permissions:` block, a `timeout-minutes`, the
#: vendored `outputHashes` — and it is one value a downstream verifier can check
#: with one `sha256sum`. Each moves when its file moves and at no other time,
#: which is the whole of [`stable`]'s requirement.
PROCEDURE = (CALLER, WORKFLOW, NIX, pathlib.Path("scripts/pt.sh"))

#: The region this script owns inside an otherwise hand-written page. Rule 9 for
#: why it is a region. The name deliberately does not start `run-count-`: that
#: prefix is `run_count_gate.MARKER`, and a region wearing it there is one that
#: gate demands to be the owner of.
REGION = "release-manifest"
REGION_HEADER = "<!-- Generated by scripts/release_gate.py --write; do not edit. -->"

#: The claim no command on this page makes, spelled ONCE. Two spellings of a word
#: a rule is about is a rule nothing can hold — `claims_gate.DISCLAIMER` records
#: what four spellings of one sentence cost. `assurance/platform.toml` writes the
#: same gap `source-to-binary` in prose; that is prose, this is the token.
FRONTIER = "source->binary"

#: The registry row that owns [`FRONTIER`], and the status under which it is open.
FRONTIER_ROW = "PLAT-TOOLCHAIN-001"
FRONTIER_STATUS = "pending"

#: What an entry may claim, and what each word means. HAND-WRITTEN, and it has to
#: be: no file in this tree says what a command establishes, only what it runs.
#: Closed on purpose — an open vocabulary lets a step be "covered" by a word
#: nobody agreed on, which is `toolchain_gate.ROLES`'s reason one file over.
SUBJECTS = {
    "admission": "which commits may become a release at all",
    "none": "produces or publishes an artifact; establishes nothing on its own",
    "inventory": "what went into the artifact",
    "bit-for-bit": "the same inputs produce the same output bytes",
    "origin": "which workflow, at which commit, on which runner built it",
    "integrity": "the bytes you have are the bytes that were published",
}

#: How a command's SHAPE decides its subject — the derivation that turns a
#: hand-written `subject` into a second copy that cannot rot silently. Ordered:
#: the first match wins, so the rebuild's `nix build` is read as the rebuild and
#: not as the plain build above it.
#:
#: [`FRONTIER`] is deliberately absent from the values, and [`frontier`] asserts
#: that rather than trusting this comment: no command in a release pipeline can
#: establish that the machine code preserves what the source says, so no entry
#: may be able to say it does.
SHAPE = (
    (re.compile(r"merge-base --is-ancestor"), "admission"),
    (re.compile(r"--rebuild"), "bit-for-bit"),
    (re.compile(r"cargo cyclonedx"), "inventory"),
    (re.compile(r"attest-build-provenance"), "origin"),
    (re.compile(r"cosign sign-blob"), "integrity"),
    (re.compile(r"sha256sum"), "integrity"),
)

#: The subject a step gets when no shape matches: it runs, and it settles
#: nothing. Named rather than typed at the comparison, because "the default" is
#: itself a claim — most steps of a release pipeline establish nothing, and a
#: manifest that let them default to a real subject would read as evidence.
UNSHAPED = "none"

#: The manifest, and the whole hand-written half of it. `step` is a substring
#: that must match exactly one step of the job — a substring and not the full
#: name because the names carry the flavor COUNT, which rule 5 already holds
#: against the list, and keying on it would make one added flavor two unrelated
#: findings. `subject` is checked against [`SHAPE`]. `statement` is prose, and it
#: is the one field nothing can derive: no file says why a step is in the
#: pipeline.
ENTRIES = (
    {
        "step": "actions/checkout",
        "subject": "none",
        "statement": "Fetches the tagged tree, deep enough that the tag gate below can read `origin/main` out of it.",
    },
    {
        "step": "DeterminateSystems/nix-installer-action",
        "subject": "none",
        "statement": "Installs Nix. The build's determinism rests on the sandbox this provides, not on the runner image.",
    },
    {
        "step": "nix-community/cache-nix-action",
        "subject": "none",
        "statement": "A cache keyed on `flake.lock`. A cache hit and a cache miss must produce the same bytes; the rebuild step is what says they do.",
    },
    {
        "step": "actions/cache",
        "subject": "none",
        "statement": "The cargo registry cache. Outside the Nix sandbox, so it feeds no shipped byte — `nix build` vendors from `Cargo.lock`.",
    },
    {
        "step": "sigstore/cosign-installer",
        "subject": "none",
        "statement": "Installs the signer. Its pin is part of the trust base: this is the code that holds the OIDC token.",
    },
    {
        "step": "resolve tag",
        "subject": "admission",
        "statement": "Shape, charset, and an ancestor-of-`main` test. Defence in depth only: an actor who can push a tag also controls this file at that ref, so the primary control is a repository tag ruleset.",
    },
    {
        "step": "build the",
        "subject": "none",
        "statement": "Produces the images. A build alone establishes nothing — it is the rebuild below that turns it into evidence.",
    },
    {
        "step": "reproducibility gate",
        "subject": "bit-for-bit",
        "statement": "Recompiles every flavor already in the store and fails on a hash mismatch, so a non-reproducible image is never published. Says the BUILD is a function of its inputs; says nothing about what the machine code means.",
    },
    {
        "step": "CycloneDX SBOM",
        "subject": "inventory",
        "statement": "The firmware crate's dependency tree, scoped to the shipped target.",
    },
    {
        "step": "checksums",
        "subject": "integrity",
        "statement": "A digest of every `.uf2` and of the SBOM. It does not cover itself, its own signature or the provenance bundle — the last two are written after this step, and the attestation is what stands behind them.",
    },
    {
        "step": "attest build provenance",
        "subject": "origin",
        "statement": "GitHub build provenance for the `.uf2` files this step is handed, bound to THIS reusable workflow's identity — the difference between SLSA Build L3 and L2.",
    },
    {
        "step": "attach the provenance bundle",
        "subject": "none",
        "statement": "An offline copy of the attestation. The API and Rekor stay authoritative; immutable releases forbid adding it later, so it is attached at create time.",
    },
    {
        "step": "sign SHA256SUMS",
        "subject": "integrity",
        "statement": "Keyless cosign over the checksum file. No private key exists: the signer is this workflow's OIDC identity.",
    },
    {
        "step": "release notes",
        "subject": "none",
        "statement": "Extracts the version's CHANGELOG section. Cosmetic, and capped because an oversized body fails the job after the tag is already pushed.",
    },
    {
        "step": "create the GitHub Release",
        "subject": "none",
        "statement": "Publishes `dist/*`. Refuses to publish a `no-touch` asset, which would ship a build with the physical-consent gate removed.",
    },
)

#: Under the measured roster. A floor on the DERIVATION, not on the procedure: an
#: entry list that collapsed, or a step parser that stopped finding steps, passes
#: every rule above by having nothing to check.
ENTRY_FLOOR = 12

#: The same, for the flavor loops. Every image the release publishes is one row.
FLAVOR_FLOOR = 10

#: An asset name the page still has to say although this workflow no longer
#: writes it, with the reason. Held BOTH ways: a name here that the page has
#: stopped saying is deleted from here, so a carve-out cannot outlive its need.
HISTORICAL = {
    "SHA256SUMS.cosign.bundle": (
        "the pre-v0.4.11 name of the same bytes; releases are immutable, so the"
        " five already published keep it and the page has to name both"
    ),
}

#: The record half, which cannot be closed from a checkout. Printed into the
#: region so a reader of the page sees the boundary without opening this file,
#: and kept as an obligation with a COST rather than as an apology.
OPEN = (
    (
        "no entry on this page is bound to a release artifact",
        "Binding one needs a `v*` tag and a `release-build.yml` run: the tag, the"
        " commit, the runner, the per-`.uf2` sha256 and the Rekor entry all come"
        " into existence there and in no checkout. Cost: one tagged release, by"
        " the maintainer, plus a manifest field per bound value and a gate rule"
        " holding it against the attestation API. Until then this page is a"
        " recipe: what a release runs, not what one ran.",
    ),
    (
        f"`{FRONTIER}` is established by nothing here",
        f"`{FRONTIER_ROW}` in `assurance/platform.toml` owns it and is still"
        f" `{FRONTIER_STATUS}`. A reproducible build is a statement about"
        " determinism; a miscompilation reproduces exactly as well as a correct"
        " compilation does.",
    ),
)


# --- reading the procedure ----------------------------------------------------

#: A step of a job: `- name: …` or `- uses: …` at the steps' own indent.
STEP = re.compile(r"^(?P<indent> +)- (?P<key>name|uses): (?P<value>.+?)\s*$")

#: A mapping key inside a step. `run:` is the one whose VALUE may be a block, so
#: the indicator is tolerated rather than captured — `gate_lines.logical_lines`
#: owns continuation joining and the block body is read by indent below.
KEY = re.compile(r"^(?P<indent> +)(?P<key>[a-z-]+):\s?(?P<value>.*?)\s*$")

#: `for pkg in a b c; do`, the shape both flavor loops use.
LOOP = re.compile(r"for pkg in (?P<list>[\w\s-]+?);\s*do")

#: A bare integer, for rule 5. Neither `2mb` nor `v7.0.1` is one.
COUNT = re.compile(r"(?<![\w.-])(\d+)(?![\w.-])")

#: A hex run long enough for git to resolve. 7 is git's own shortest unambiguous
#: abbreviation; above 40 it is not a commit id and cannot be one, so a sha256
#: digest is out of reach by length rather than by a carve-out. Case-insensitive
#: rather than `[0-9a-f]`: git resolves an upper-case abbreviation perfectly well,
#: and a rule that reads only one case is one an upper-case spelling walks past.
HEXRUN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{7,40}(?![0-9a-fA-F])")

#: The English spellings of a small count, so rule 5b holds both halves of what
#: this page actually says: `the 14 .uf2 flavors` and `rebuilds all fourteen
#: flavors` are one number in two spellings, and a rule reading only digits is a
#: rule the second walks past — `claims_gate.DISCLAIMER` records what one
#: sentence in four spellings cost.
WORDS = (
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen", "twenty",
)

#: A count of the published images, in the page's own prose, in either spelling.
#: The nouns are closed: a wider rule reads `v0.4.10` and `SHA256SUMS` as counts.
#: The optional `firmware` is not decoration — `docs/releases.md` says "Fourteen
#: firmware images", and without it that page's only count is unheld.
PAGE_COUNT = re.compile(
    r"(?<![\w.-])(\d+|"
    + "|".join(WORDS)
    + r")\s+(?:firmware\s+)?(?:`?\.uf2`?|flavou?rs?|images?)\b",
    re.I,
)

#: A step key that decides whether a step RUNS, and a shell suffix that swallows
#: its failure. [`SHAPE`] reads a command's text and can never read its effect,
#: so a step switched off in place is one this manifest would go on printing as
#: live — measured by review: `if: false` on the reproducibility gate was exit 0
#: with the page still saying a non-reproducible image is never published.
DISARM_KEYS = ("if", "continue-on-error")
DISARM_SUFFIX = re.compile(r"\|\|\s*(?:true|:)\s*$")


def steps(text: str) -> list[dict]:
    """The ordered steps of the workflow's one job, each with its `run:` body.

    A hand parser and not a YAML load, for the reason every guard in `scripts/`
    is one: the tree ships no YAML library in the gate's environment, and the
    two facts wanted here — the order of the steps and the literal text of each
    `run:` — are exactly what a loader normalises away.
    """
    out: list[dict] = []
    current: dict | None = None
    depth: int | None = None
    for raw in text.splitlines():
        found = STEP.match(raw)
        if found and (depth is None or len(found["indent"]) == depth):
            depth = len(found["indent"])
            current = {
                "name": None, "uses": None, "run": [], "keys": set(),
                "body": depth + 2, "at": None,
            }
            current[found["key"]] = found["value"]
            current["keys"].add(found["key"])
            out.append(current)
            continue
        if current is None:
            continue
        indent = len(raw) - len(raw.lstrip())
        if raw.strip() and indent <= depth:
            current = None
            continue
        key = KEY.match(raw)
        if key and len(key["indent"]) == current["body"]:
            current["keys"].add(key["key"])
            if key["key"] in ("name", "uses"):
                current[key["key"]] = key["value"]
            current["at"] = current["body"] if key["key"] == "run" else None
            if key["key"] == "run" and key["value"] not in ("|", ">", ""):
                current["run"].append(key["value"])
            continue
        if current["at"] is not None and (not raw.strip() or indent > current["at"]):
            current["run"].append(raw)
    for step in out:
        step["title"] = step["name"] or (step["uses"] or "").split("@")[0]
        step["block"] = "\n".join(step["run"])
        step["code"] = commands(step["block"])
        step["shape"] = " ".join([step["uses"] or "", *step["code"]])
    return out


def step_items(text: str) -> tuple[int, int]:
    """(how many `steps:` blocks, how many list items in them).

    The completeness half of the parser itself, and the hole every other rule
    here is blind to by construction: [`STEP`] recognises a step by its `name:`
    or `uses:` key and pins the indent to the FIRST one it sees, so a bare
    `- run: …` step, and every step of a second job written at a different
    indent, is not a step this file has ever seen — not claimed, not printed,
    and not a finding either. Rule 1's "claimed by no entry" cannot see them,
    because it iterates what the parser returned.

    Counted from `steps:` down rather than from the first `- name:`, and both
    numbers returned, because a whole second job was measured past the first
    version: `grep -c mirror docs/supply-chain.md` answered 0 for a job whose
    `scp dist/* mirror:/pub` a release would have run.
    """
    lines = text.splitlines()
    blocks, items, index = 0, 0, 0
    while index < len(lines):
        opened = re.match(r"^(?P<indent>\s*)steps:\s*$", lines[index])
        if not opened:
            index += 1
            continue
        blocks += 1
        depth, level = len(opened["indent"]), None
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= depth:
                break
            found = re.match(r"^(?P<indent>\s*)- \S", line)
            if found:
                here = len(found["indent"])
                level = here if level is None else level
                items += here == level
            index += 1
    return blocks, items


def commands(block: str) -> list[str]:
    """The lines of a `run:` block that RUN, continuations joined, comments cut.

    `gate_lines.split_at_comment` and not a `startswith("#")`: `true # cargo …`
    runs the `true`, and reading a whole line as a comment because it ends in one
    is the hole two guards in this directory shipped with.
    """
    out = []
    for _indent, body in gate_lines.logical_lines(block):
        code = gate_lines.split_at_comment(body)[0].strip()
        if code:
            out.append(code)
    return out


def flavor_loops(job: list[dict]) -> list[tuple[str, list[str]]]:
    """(step title, the packages its `for pkg in` iterates), in file order.

    Over the step's CODE and not its raw block: read raw, a commented-out
    `# for pkg in firmware firmware-pqc; do` is a third loop, and a rule that
    compares the first two then has a loop it never looked at. Measured by
    review at exit 0.
    """
    return [
        (step["title"], found["list"].split())
        for step in job
        for command in step["code"]
        for found in LOOP.finditer(command)
    ]


def nix_packages(text: str) -> dict[str, dict[str, str]]:
    """{package: its `mkFirmware` arguments} out of `nix/firmware.nix`.

    Comments are cut first, so a package named only in the prose above the set —
    and `nix/firmware.nix` names several — is not read as one that exists.
    """
    code = re.sub(r"(?m)^\s*#.*$", "", text)
    head = re.compile(r"^    (?P<name>[\w-]+) = mkFirmware \{", re.M)
    arg = re.compile(r'(?P<key>\w+) = (?P<value>"[^"]*"|\[[^\]]*\])\s*;')
    out = {}
    for found in head.finditer(code):
        body, depth, index = None, 0, found.end() - 1
        while index < len(code):
            depth += (code[index] == "{") - (code[index] == "}")
            if depth == 0:
                body = code[found.end() - 1 : index]
                break
            index += 1
        if body is None:
            continue
        out[found["name"]] = {
            a["key"]: " ".join(a["value"].split()) for a in arg.finditer(body)
        }
    return out


def selection(args: dict[str, str]) -> str:
    """A flavor's build selection, as one readable phrase.

    The `cargoFlags` list and the declarative knobs are two different mechanisms
    — a feature reaches `cargo`, a knob reaches `build.rs` through the
    derivation's environment — and both decide which bytes come out, so a
    manifest that printed only the features would describe eleven of fourteen
    images and silently mis-describe three.
    """
    parts = []
    flags = args.get("cargoFlags", "")
    features = re.findall(r'"--features"\s+"([^"]+)"', flags)
    if features:
        parts.append(f"`--features {','.join(features)}`")
    for key, value in args.items():
        if key in ("name", "cargoFlags"):
            continue
        parts.append(f"`{key} = {value}`")
    return ", ".join(parts) or "no flags, no knobs"


def phases(text: str) -> dict[str, list[str]]:
    """{phase: the commands it runs} out of `nix/firmware.nix`'s `''…''` blocks."""
    block = re.compile(r"^\s*(?P<phase>\w+Phase) = ''\n(?P<body>.*?)\n\s*'';", re.S | re.M)
    out = {}
    for found in block.finditer(text):
        body = re.sub(r"(?m)^\s*#.*$", "", found["body"])
        body = re.sub(r"\\\n\s*", " ", body)
        out[found["phase"]] = [
            " ".join(line.split())
            for line in body.splitlines()
            if line.strip() and not line.strip().startswith("runHook")
        ]
    return out


#: The tag, as the workflow spells it in a path. Normalised to one placeholder so
#: an asset the page names and an asset the workflow writes are comparable.
TAGREF = re.compile(r"\$\{\{\s*steps\.tag\.outputs\.tag\s*\}\}|\$\{tag\}|\$tag")


def assets(job: list[dict], labels: list[str]) -> list[str]:
    """Every file this job publishes, as a name template.

    `gh release create … dist/*` uploads the directory wholesale, so the
    published set is "whatever any step wrote into `dist/`" — two shapes, because
    the checksums step `cd dist` first and then redirects into a bare name.
    """
    found = set()
    for step in job:
        for command in step["code"]:
            # The tag placeholder carries SPACES (`${{ steps.tag.outputs.tag }}`),
            # so it is folded to one token BEFORE the path is read off. Reading
            # first stops at the space and yields `rs-key-${{`, which is what the
            # asset rule reported the first time this ran.
            command = TAGREF.sub("<tag>", command)
            found.update(re.findall(r"dist/([\w.${}<>-]+)", command))
            if "cd dist" in step["block"]:
                found.update(re.findall(r">\s*([\w.-]+)\s*$", command))
    out = set()
    for name in found:
        if not name or name == "*":
            continue
        if "${label}" in name:
            out.update(name.replace("${label}", label) for label in labels)
        else:
            out.add(name)
    return sorted(out)


def label_of(package: str) -> str:
    """The published label of a flavor, by the workflow's own rule."""
    label = package[len("firmware") :].lstrip("-") if package.startswith("firmware") else package
    return label or "default"


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_commit(root: pathlib.Path, hexish: str) -> bool:
    """Whether `hexish` names a commit of THIS repository.

    Asked of git rather than compared against `HEAD`, because the value a
    "which revision" field would carry is stale one commit later whether it is
    the tip or an ancestor. A foreign repository's action pin resolves to
    nothing here, which is why the six of them are not findings.
    """
    done = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", f"{hexish}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    return done.returncode == 0


# --- the rules ----------------------------------------------------------------


def check_parser_complete(root: pathlib.Path, findings: list[str]) -> None:
    """Rule 1b: one job, and every list item in it came back as a step."""
    text = (root / WORKFLOW).read_text(encoding="utf-8")
    blocks, items = step_items(text)
    if blocks != 1:
        findings.append(
            f"{WORKFLOW} carries {blocks} `steps:` block(s) — this manifest reads"
            " ONE job, so a second one's commands are released and printed"
            " nowhere"
        )
    missed = items - len(steps(text))
    if missed:
        findings.append(
            f"{WORKFLOW} carries {missed} step(s) this parser does not see — a"
            " step with neither a `name:` nor a `uses:`, or one at another"
            " indent, is invisible to every rule here, including the one that"
            " refuses an unclaimed step"
        )


def check_disarmed(job: list[dict], findings: list[str]) -> None:
    """Rule 1c: no step of the release job is switched off or made non-fatal.

    [`SHAPE`] reads a command's TEXT and can never read its effect, so this is
    the one shape of "the manifest describes a pipeline the repo does not run"
    that is cheap to refuse outright rather than to model.
    """
    for step in job:
        keys = sorted(step["keys"] & set(DISARM_KEYS))
        if keys:
            findings.append(
                f"{WORKFLOW}'s step {step['title']!r} carries {keys} — a step"
                " that may not run is one this page would go on printing as a"
                " command a release runs"
            )
        for command in step["code"]:
            if DISARM_SUFFIX.search(command):
                findings.append(
                    f"{WORKFLOW}'s step {step['title']!r} swallows a failure"
                    f" with {command!r} — a release step that cannot fail is a"
                    " gate that cannot gate"
                )


def pair_steps(job: list[dict]) -> dict[str, list[dict]]:
    """{entry step key: the steps it names} — the derivation rule 1 judges.

    Split from the judgement so the rule can be removed in a test without taking
    the pairing with it: an arm that deletes both proves nothing about which of
    the two found the break.
    """
    return {
        entry["step"]: [step for step in job if entry["step"] in (step["title"] or "")]
        for entry in ENTRIES
    }


def match_steps(job: list[dict], findings: list[str]) -> dict[str, dict]:
    """Rule 1, both ways. {entry step key: the step it names}."""
    paired: dict[str, dict] = {}
    claimed: dict[int, str] = {}
    for key, hits in pair_steps(job).items():
        if not hits:
            findings.append(
                f"the manifest entry `{key}` names no step of {WORKFLOW} — a"
                " renamed or deleted step leaves its entry describing nothing"
            )
            continue
        if len(hits) > 1:
            findings.append(
                f"the manifest entry `{key}` names {len(hits)} steps of"
                f" {WORKFLOW} ({', '.join(repr(h['title']) for h in hits)}) — a"
                " key that matches more than one describes neither"
            )
            continue
        if id(hits[0]) in claimed:
            # The direction the entry->step half cannot see: both keys match one
            # step each, so both are legal, and `body()`'s last-match-wins drops
            # one statement on the floor. Measured by review at exit 0.
            findings.append(
                f"the manifest entries `{claimed[id(hits[0])]}` and `{key}` both"
                f" name {WORKFLOW}'s step {hits[0]['title']!r} — one of the two"
                " statements is printed and the other silently is not"
            )
            continue
        paired[key] = hits[0]
        claimed[id(hits[0])] = key
    for step in job:
        if id(step) not in claimed:
            findings.append(
                f"{WORKFLOW}'s step {step['title']!r} is claimed by no manifest"
                " entry — a step nothing names is a released command this page"
                " does not print"
            )
    return paired


def check_subjects(paired: dict[str, dict], findings: list[str]) -> None:
    """Rule 2: the hand-written subject against the command's own shape."""
    for entry in ENTRIES:
        step = paired.get(entry["step"])
        if step is None:
            continue
        said, derived = entry["subject"], subject_of(step)
        if said == FRONTIER:
            findings.append(
                f"the entry for {step['title']!r} claims `{FRONTIER}` and the"
                f" command it runs establishes `{derived}` — determinism is not"
                " semantic preservation: a miscompilation rebuilds"
                f" bit-identically. `{FRONTIER}` is `{FRONTIER_ROW}`'s open"
                " obligation, never a result of this pipeline"
            )
        elif said not in SUBJECTS:
            findings.append(
                f"the entry for {step['title']!r} carries the subject `{said}`,"
                f" which is not one of {', '.join(sorted(SUBJECTS))}"
            )
        elif said != derived:
            findings.append(
                f"the entry for {step['title']!r} says its subject is `{said}`"
                f" and the command it runs establishes `{derived}`"
            )


def subject_of(step: dict) -> str:
    for pattern, subject in SHAPE:
        if pattern.search(step["shape"]):
            return subject
    return UNSHAPED


def check_frontier_unreachable(findings: list[str]) -> None:
    """Rule 3a, asserted rather than assumed.

    [`check_subjects`] refuses an ENTRY that claims the frontier. This refuses
    the mechanism that would make such an entry legal — a shape mapping onto it,
    or the word appearing in the vocabulary — because the entry rule reads a
    hand-written field and a widened map would make the claim derivable instead.
    """
    if FRONTIER in {subject for _pattern, subject in SHAPE} or FRONTIER in SUBJECTS:
        findings.append(
            f"`{FRONTIER}` is reachable as an entry's subject — no command in a"
            " release pipeline establishes that the machine code preserves what"
            " the source says, so no entry may be able to claim it"
        )


def check_frontier_open(root: pathlib.Path, findings: list[str]) -> None:
    """Rule 3b: the page prints the frontier as open exactly while the registry
    row that owns it says so — both directions, because a page still calling a
    settled question open is the same defect as the reverse."""
    registry = tomllib.loads((root / PLATFORM).read_text(encoding="utf-8"))
    rows = [row for row in registry.get("assumption", []) if row.get("id") == FRONTIER_ROW]
    if not rows:
        findings.append(
            f"{PLATFORM} has no `{FRONTIER_ROW}` row, and this page prints"
            f" `{FRONTIER}` as open against it"
        )
        return
    status = rows[0].get("status")
    if status != FRONTIER_STATUS:
        findings.append(
            f"{FRONTIER_ROW} is `{status}` and this page still prints"
            f" `{FRONTIER}` as an open obligation against it — settle the page"
            " or the registry, not neither"
        )


#: How many `for pkg in` loops the job runs: the build and the reproducibility
#: gate, and nothing else. EXACTLY, not at least: a third loop makes "the first
#: two agree" a statement about a pair somebody chose.
LOOPS = 2


def check_loops_present(loops, findings: list[str]) -> list[str]:
    """Rule 4a. The built list, and that there are exactly two loops to compare."""
    if len(loops) != LOOPS:
        findings.append(
            f"{WORKFLOW} carries {len(loops)} `for pkg in` loop(s) and this"
            f" manifest reads {LOOPS} — the build and the reproducibility gate."
            " A gate that iterates nothing publishes every image unchecked, and"
            " a third loop leaves one of them compared against nothing"
        )
    return loops[0][1] if loops else []


def check_loops_agree(loops, findings: list[str]) -> None:
    """Rule 4b, and the one worth the most: a rebuild gate covering thirteen of
    fourteen images publishes the fourteenth unchecked, and every other rule here
    stays green while it does.

    Every loop against the FIRST, not `loops[0]` against `loops[1]`: with a third
    loop present the pairwise form compares two lists that agree and never looks
    at the one that does not. Measured by review at exit 0.
    """
    for title, packages in loops[1:]:
        if packages != loops[0][1]:
            findings.append(
                f"{WORKFLOW}'s {loops[0][0]!r} builds {len(loops[0][1])}"
                f" flavor(s) and {title!r} rebuilds {len(packages)}"
                f" ({sorted(set(loops[0][1]) ^ set(packages))} differ) — an image"
                " the reproducibility gate skips is published unchecked"
            )


def check_packages_exist(flavors, packages, findings: list[str]) -> None:
    """Rule 4c: the workflow may only build images `nix/firmware.nix` defines."""
    missing = [name for name in flavors if name not in packages]
    if missing:
        findings.append(
            f"{WORKFLOW} builds {missing}, which {NIX} has no `mkFirmware`"
            " package for"
        )


def check_no_touch(flavors, packages, findings: list[str]) -> None:
    """Rule 4d. The workflow refuses a `no-touch` ASSET at publish time by its
    NAME; this refuses one entering the loop, by its name AND by the feature it
    actually compiles.

    The feature half is the one that matters, measured by review: a package
    called `firmware-testing` carrying `--features no-touch` walks past a name
    test here and past the workflow's own `ls dist/*no-touch*`, because its
    published label is `testing`. A signed presence-bypass asset removes the
    physical-consent gate from an end-user build.
    """
    presence = sorted(
        {
            name
            for name in flavors
            if "no-touch" in name or "no-touch" in packages.get(name, {}).get("cargoFlags", "")
        }
    )
    if presence:
        findings.append(
            f"{WORKFLOW} would publish {presence} — a `no-touch` build"
            " auto-confirms user presence and must never be released"
        )


def check_flavor_floor(flavors, floor: int, findings: list[str]) -> None:
    """Rule 10, the flavor half."""
    if len(flavors) < floor:
        findings.append(
            f"{len(flavors)} flavor(s) read out of {WORKFLOW}, under the measured"
            f" {floor} — every rule here is satisfied by a loop over nothing"
        )


def check_counts(job, loops, findings: list[str]) -> None:
    """Rule 5: a number typed about the flavor set, against the set."""
    for title, flavors in loops:
        step = next((s for s in job if s["title"] == title), None)
        if step is None:
            continue
        # Every command of the step, not only its `echo` lines: rewriting one as
        # `printf '%s\n' "all 7 flavors rebuilt"` was measured past the narrower
        # form at exit 0, with the region printing the wrong number itself.
        typed = [
            (int(value), where)
            for where in [step["title"] or "", *step["code"]]
            for value in COUNT.findall(where)
        ]
        for value, where in typed:
            if value != len(flavors):
                findings.append(
                    f"{WORKFLOW} says {value} in {where!r} and the loop beside"
                    f" it iterates {len(flavors)} flavor(s)"
                )


def check_page_count(root: pathlib.Path, flavors, findings: list[str]) -> None:
    """Rule 5b: the count the PAGES type, against the list the workflow builds.

    Rule 5 holds the workflow's own step names; this holds the sentences a reader
    actually reads, in both spellings. The pages said "the 14 `.uf2` flavors",
    "rebuilds all fourteen flavors" and "Fourteen firmware images" when this was
    written, and none was read by anything.
    """
    want = {str(len(flavors))}
    if len(flavors) < len(WORDS):
        want.add(WORDS[len(flavors)])
    for page in PAGES:
        for found in PAGE_COUNT.finditer(hand_written(root, page)):
            if found.group(1).lower() not in want:
                findings.append(
                    f"{page} says {found.group(0)!r} and {WORKFLOW} builds"
                    f" {len(flavors)} flavor(s) — the sentence a reader takes the"
                    " number from is not the list the release iterates"
                )


def check_caller(root: pathlib.Path, findings: list[str]) -> None:
    """Rule 6: the thin caller calls this builder and NOTHING ELSE.

    "and nothing else" measured by review: a second `uses:` job in the caller
    moves half a release into a workflow this manifest never opens, and the
    membership form of this rule was exit 0 on it.
    """
    text = (root / CALLER).read_text(encoding="utf-8")
    called = re.findall(r"^\s+uses:\s*(\S+\.ya?ml)\s*$", text, re.M)
    want = f"./{WORKFLOW}"
    if called != [want]:
        findings.append(
            f"{CALLER} calls {called or 'nothing'} and this manifest reads"
            f" [{want!r}] — the reusable builder's identity is what the published"
            " `cosign verify-blob --certificate-identity-regexp` checks and what"
            " makes the provenance SLSA Build L3 rather than L2, and a second"
            " called workflow is a release step printed nowhere"
        )


#: What `gh release create` uploads. Captured as the trailing operands so the
#: published set can be held against it: `dist/*` uploads everything the job
#: wrote, and `dist/*.uf2` — measured by review at exit 0 — uploads none of the
#: checksums, the signature, the SBOM or the provenance bundle while this page
#: went on listing all four.
UPLOAD = re.compile(r"gh release create\b(?P<args>.*)$")

#: A command that puts a file somewhere. Its last operand is checked, because
#: `cp "$out/$pkg.elf" dist/` names no file this parser can print and was
#: measured by review to add fourteen unsigned ELFs to a release invisibly.
WRITER = re.compile(r"^(?P<verb>cp|mv|install)\s")


def check_uploaded(job, published, findings: list[str]) -> None:
    """Rule 8c: every asset this manifest lists is one the release step uploads.

    The two halves are different questions and only the first was asked before:
    what a step WRITES into `dist/`, and what `gh release create` UPLOADS out of
    it. A narrowed upload glob publishes fewer files than this page names, and
    the page's verify commands then describe a download nobody gets.
    """
    patterns = []
    for step in job:
        for command in step["code"]:
            found = UPLOAD.search(command)
            if found:
                patterns += [
                    word for word in found["args"].split() if word.startswith("dist/")
                ]
    if not patterns:
        findings.append(
            f"{WORKFLOW} has no `gh release create` operand under `dist/` — this"
            " manifest cannot say which of the files the job wrote are published"
        )
        return
    missed = [
        name
        for name in published
        if not any(fnmatch.fnmatch(f"dist/{name}", pattern) for pattern in patterns)
    ]
    if missed:
        findings.append(
            f"{WORKFLOW} writes {missed} into `dist/` and uploads only"
            f" {patterns} — this page lists an asset the release does not publish"
        )


def check_named_writes(job, findings: list[str]) -> None:
    """Rule 8d: nothing is copied into `dist/` under a name this parser cannot read.

    A bare directory target (`cp x dist/`) keeps the source's basename, which is
    a shell expansion this file does not evaluate — so the file is published,
    covered by no digest, and named on no page.
    """
    for step in job:
        for command in step["code"]:
            if not WRITER.match(command):
                continue
            target = command.split()[-1].strip("\"'")
            if target.rstrip("/") == "dist":
                findings.append(
                    f"{WORKFLOW}'s step {step['title']!r} runs {command!r} — a"
                    " bare `dist/` target keeps the source's basename, so the"
                    " file is published under a name this page cannot print"
                )


def hand_written(root: pathlib.Path, page: pathlib.Path) -> str:
    """`page` with every GENERATED region blanked — the half a person types.

    `claims_gate.mask_regions`, not a cut of this generator's own markers: the
    toolchain table shares one of these pages, and a rule that read a generated
    region would be holding a derivation against itself. Same mechanism the
    claims row uses, derived from the marker SHAPE, so a region added later is
    masked without this file learning its name.
    """
    return claims_gate.mask_regions((root / page).read_text(encoding="utf-8"))


#: A release-asset name as a page writes it. `<flavor>` is a spelling of its own:
#: `docs/releases.md` names the whole family in one line rather than a label at a
#: time, and expanding it here is what lets that page be read by the same rule.
ASSET = re.compile(r"(?<![\w./-])(?:rs-key-[\w<>-]+|SHA256SUMS)(?:\.\w+)*")

#: A fenced block. The historical asset name is legal in PROSE — five published
#: releases carry it and cannot be renamed — and not in a command, which is what
#: a reader copies. Measured by review: pointing the page's own
#: `cosign verify-blob --bundle` at the dead name was exit 0.
FENCE = re.compile(r"^```.*?^```", re.M | re.S)


def page_assets(root: pathlib.Path, page: pathlib.Path) -> set[str]:
    """The release-asset names the HAND-WRITTEN half of `page` says."""
    return set(ASSET.findall(hand_written(root, page)))


def check_assets_named(root, published, findings: list[str]) -> None:
    """Rule 8a, in the direction the rot already went once in this tree: the page
    names a file, the workflow renames it, and nothing notices until somebody
    downloads a release and runs a verify command against a name that is gone."""
    family = set(published) | {
        re.sub(r"-[\w-]+\.uf2$", "-<flavor>.uf2", name) for name in published
    }
    for page in PAGES:
        for name in sorted(page_assets(root, page)):
            if name in family or name in HISTORICAL:
                continue
            findings.append(
                f"{page} names the release asset `{name}` and {WORKFLOW} writes"
                f" {published} — the page's verify commands are about a file that"
                " is not published"
            )


def check_historical_used(root, findings: list[str]) -> None:
    """Rule 8b: the carve-out both ways, so it cannot outlive its reason — and
    only in prose, because a dead name inside a fenced block is a command a
    reader copies."""
    named = {name for page in PAGES for name in page_assets(root, page)}
    for name, why in sorted(HISTORICAL.items()):
        if name not in named:
            findings.append(
                f"`{name}` is carved out here as {why!r} and no page of"
                f" {[str(p) for p in PAGES]} names it — a carve-out that outlives"
                " its reason is one nobody can judge"
            )
        for page in PAGES:
            code = "\n".join(FENCE.findall(hand_written(root, page)))
            if name in code:
                findings.append(
                    f"{page} names `{name}` inside a fenced block — the carve-out"
                    " is for prose about five immutable releases, and a command a"
                    " reader copies must name the file this workflow writes"
                )


def region_of(text: str) -> str:
    """Just this generator's region out of a whole page.

    [`stable`] took the rendered PAGE at first, so it was reading the toolchain
    table's flake revisions too — harmless, since neither is a commit here, but
    a finding about another region wearing this one's name is a finding nobody
    can act on.
    """
    start, end = f"<!-- {REGION}:start -->", f"<!-- {REGION}:end -->"
    head, tail = text.find(start), text.find(end)
    return text[head : tail + len(end)] if head != -1 and tail > head else ""


def stable(root: pathlib.Path, text: str, findings: list[str]) -> None:
    """Rule 7: no value in the region changes with this repository's HEAD."""
    for found in sorted(set(HEXRUN.findall(region_of(text)))):
        if is_commit(root, found):
            findings.append(
                f"the `{REGION}` region would carry `{found}`, which names a"
                " commit of this repository — a generated region holding one is"
                " dirty on the next commit, and the row that diffs it becomes a"
                " nuisance rather than a guard"
            )


# --- the audit ----------------------------------------------------------------


def read(root: pathlib.Path):
    """Everything the region is rendered from, read once."""
    job = steps((root / WORKFLOW).read_text(encoding="utf-8"))
    nix = (root / NIX).read_text(encoding="utf-8")
    packages = nix_packages(nix)
    loops = flavor_loops(job)
    return job, packages, loops, phases(nix)


def check_entry_floor(floor: int, findings: list[str]) -> None:
    """Rule 10, the entry half."""
    if len(ENTRIES) < floor:
        findings.append(
            f"{len(ENTRIES)} manifest entr(ies), under the measured {floor} — a"
            " roster that collapsed keeps every rule above green by having"
            " nothing to hold"
        )


def check_region(root: pathlib.Path, want: str, findings: list[str]) -> None:
    """Rule 9: the page carries what the generator writes, byte for byte."""
    if (root / PAGE).read_text(encoding="utf-8") != want:
        findings.append(
            f"{PAGE}'s `{REGION}` region is not what the generator writes —"
            " run `python scripts/release_gate.py --write` and commit it"
        )


def audit(
    root: pathlib.Path,
    entry_floor: int = ENTRY_FLOOR,
    flavor_floor: int = FLAVOR_FLOOR,
):
    findings: list[str] = []
    job, packages, loops, built = read(root)
    check_parser_complete(root, findings)
    check_disarmed(job, findings)
    paired = match_steps(job, findings)
    check_subjects(paired, findings)
    check_frontier_unreachable(findings)
    check_frontier_open(root, findings)
    flavors = check_loops_present(loops, findings)
    check_loops_agree(loops, findings)
    check_packages_exist(flavors, packages, findings)
    check_no_touch(flavors, packages, findings)
    check_flavor_floor(flavors, flavor_floor, findings)
    check_counts(job, loops, findings)
    check_page_count(root, flavors, findings)
    check_caller(root, findings)
    published = assets(job, [label_of(name) for name in flavors])
    check_uploaded(job, published, findings)
    check_named_writes(job, findings)
    check_assets_named(root, published, findings)
    check_historical_used(root, findings)
    check_entry_floor(entry_floor, findings)

    try:
        want = render(root, job, packages, flavors, built, published)
    except (OSError, ValueError) as error:
        findings.append(f"{PAGE} cannot be generated: {error}")
    else:
        stable(root, want, findings)
        check_region(root, want, findings)

    summary = (
        f"release-gate: ok — {len(ENTRIES)} step(s) over"
        f" {len({e['subject'] for e in ENTRIES})} subject(s),"
        f" {len(flavors)} flavor(s) built and rebuilt,"
        f" {len([s for s in job if s['uses']])} action pin(s),"
        f" {len(PROCEDURE)} procedure file(s) digested,"
        f" {len(published)} published asset(s);"
        f" {FRONTIER} open against {FRONTIER_ROW}"
    )
    return findings, summary


# --- the region ---------------------------------------------------------------


def cell(text: str) -> str:
    """A markdown table cell. `|` inside a command ends the row otherwise."""
    return text.replace("|", "\\|")


def body(root, job, packages, flavors, built, published) -> list[str]:
    out = [
        f"<!-- {REGION}:start -->",
        REGION_HEADER,
        "",
        "Generated by `scripts/release_gate.py` from "
        + ", ".join(f"`{path}`" for path in PROCEDURE[:-1])
        + f" and `{PROCEDURE[-1]}`. Every command and every input below was read"
        " out of those files on the run that wrote this table; a file that no"
        " longer says the same thing fails `check.sh`.",
        "",
        "**This is a recipe, not a record.** It says what a release runs, over"
        " which inputs. It is bound to no tag, no commit and no artifact — see"
        " the open obligations at the end.",
        "",
        "**Two words that are not each other.**",
        "",
        "- **`bit-for-bit`** — the same inputs produce the same output bytes. A"
        " property of the build, established below.",
        f"- **`{FRONTIER}`** — the emitted machine code does what the source"
        " says. A property of the compiler, established by nothing here."
        f" `{FRONTIER_ROW}` in"
        " [`assurance/platform.toml`](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/platform.toml)"
        f" owns it and is `{FRONTIER_STATUS}`; it writes the same gap"
        " `source-to-binary` in prose.",
        "",
        "A miscompilation reproduces exactly as well as a correct compilation"
        " does, so no rebuild can settle the second word. The `subject` column"
        " is held against the shape of each step's own command, and the second"
        " word is not a value that column can take.",
        "",
        "### The steps a release runs",
        "",
        "| # | Step | Subject | What it settles |",
        "|---|---|---|---|",
    ]
    said = {}
    for entry in ENTRIES:
        for step in job:
            if entry["step"] in (step["title"] or ""):
                said[id(step)] = entry["statement"]
    for number, step in enumerate(job, 1):
        out.append(
            f"| {number} | {cell(step['title'])} | `{subject_of(step)}` |"
            f" {cell(said.get(id(step), '—'))} |"
        )
    out += [
        "",
        "The commands those steps run, as this gate reads them: `\\`"
        " continuations joined, and everything from the first ` #` on a line"
        " dropped — which also truncates a line whose *string* holds one.",
        "",
        "```sh",
    ]
    for number, step in enumerate(job, 1):
        if step["uses"]:
            out.append(f"# {number}. uses: {step['uses']}")
            continue
        out.append(f"# {number}. {step['title']}")
        out += step["code"]
    out += [
        "```",
        "",
        "### The image each flavor is",
        "",
        "The build step and the reproducibility gate iterate the same list, and"
        " a difference between them is a `check.sh` failure. Every published"
        f" image is `{NIX}`'s package of the same name.",
        "",
        "| Flavor | Published as | Build selection |",
        "|---|---|---|",
    ]
    for name in flavors:
        out.append(
            f"| `{name}` | `rs-key-<tag>-{label_of(name)}.uf2` |"
            f" {cell(selection(packages.get(name, {})))} |"
        )
    out += [
        "",
        "### Inside the sandbox",
        "",
        f"What `nix build .#<flavor>` runs, out of `{NIX}`:",
        "",
        "```sh",
    ]
    for phase in ("buildPhase", "installPhase"):
        out += [f"# {phase}"] + built.get(phase, [])
    out += [
        "```",
        "",
        "### Inputs",
        "",
        "The files that decide what a release is. A digest here covers the parts"
        " the tables above do not print, and it moves when its file moves and at"
        " no other time.",
        "",
        "| File | sha256 |",
        "|---|---|",
    ]
    for path in PROCEDURE:
        out.append(f"| `{path}` | `{digest(root / path)}` |")
    out += [
        "",
        "The CI code that runs them, pinned by commit:",
        "",
        "| Action | Pin | Release |",
        "|---|---|---|",
    ]
    for step in job:
        if not step["uses"]:
            continue
        name, _, rest = step["uses"].partition("@")
        pin, _, tag = rest.partition("#")
        out.append(f"| `{name}` | `{pin.strip()}` | {cell(tag.strip()) or '—'} |")
    out += [
        "",
        "The toolchain closure — `flake.lock`, `Cargo.lock` and the tools they"
        " pin — is the table above this section, and is deliberately not"
        " restated here: one copy, one place it can rot.",
        "",
        "Published assets: "
        + ", ".join(f"`{name}`" for name in published)
        + ".",
        "",
        "### What this table does not read",
        "",
        "- a step's `with:` and `env:` blocks. They are inside the digest above"
        " and are printed nowhere, so a statement in the table must not rest on"
        " one — `subject-path`, `fetch-depth` and `COSIGN_YES` are settings this"
        " page describes only in the round.",
        "- the workflow's own header comments. They are prose about the"
        " procedure, not the procedure.",
        "- what a command MEANS. The `subject` column is decided by a command's"
        " shape; a step that is present, spelled right and wrong about the world"
        " is outside every rule here.",
        "",
        "### Open obligations",
        "",
    ]
    out += [f"- **{what}.** {why}" for what, why in OPEN]
    out += [
        "",
        f"<!-- {REGION}:end -->",
    ]
    return out


def render(root, job, packages, flavors, built, published) -> str:
    text = (root / PAGE).read_text(encoding="utf-8")
    start, end = f"<!-- {REGION}:start -->", f"<!-- {REGION}:end -->"
    head, tail = text.find(start), text.find(end)
    if head == -1 or tail == -1 or tail < head:
        raise ValueError(f"{PAGE} needs exactly one {REGION!r} marker pair")
    written = "\n".join(body(root, job, packages, flavors, built, published))
    return text[:head] + written + text[tail + len(end) :]


def run(root: pathlib.Path, write: bool = False) -> int:
    if write:
        job, packages, loops, built = read(root)
        flavors = loops[0][1] if loops else []
        published = assets(job, [label_of(name) for name in flavors])
        (root / PAGE).write_text(
            render(root, job, packages, flavors, built, published), encoding="utf-8"
        )
        print(f"release-gate: wrote the {REGION} region of {PAGE}")
        return 0
    findings, summary = audit(root)
    if findings:
        print("release-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: release_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
