#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold every published sentence about a registered property to the registry.

Stage 0 п.3 and the last exit of stage 4 are ONE predicate — "a public claim
about a P0-family id is generated from the registry; one written by hand fails on
a docs row" — and it was closed by nothing. Measured before this file existed:
four false hand-written sentences, including "`SEC-FIDO-001` … PROVEN on
hardware" in `README.md`, gave EXIT=0 on all eight gates, because `scripts/
check.sh` carried no docs row at all and the CI step `docs.sh check` is `mdbook
build` plus `lychee --offline`.

**The literal criterion is not the one implemented, and the difference is stated
rather than hidden.** "Every sentence is GENERATED" would refuse
`docs/store-refinement.md`'s "which is why `SEC-STORE-002` is `BOUNDED` and not
more" — a true sentence doing work no generated table does. What is implemented
is the half that carries the risk: a hand-written status is accepted only when it
is the status the registry HOLDS for the id in the same sentence. So a true copy
stays and stops being able to rot; a copy that is wrong the day it is typed is
refused; and `PROVEN`, which is no row's status anywhere in this tree, is refused
of every id by construction — which is the measured failure above.

Two rules, and both are about a COPY:

* a sentence naming registered ids and an evidence word none of them holds is
  refused. Sentence and not paragraph, measured: over the shipped corpus the
  paragraph window reports two refusals and both are contrastive prose — "…
  `SEC-STORE-003` and `SEC-STORE-004` stay MODELLED-ONLY" beside the word
  `BOUNDED` about neither of them — while the sentence window reports zero and
  still catches all three injected false claims;
* a LINE carrying an id, a status and three or more bare integers is a
  transcribed row of the derived evidence vector, and belongs to the generator
  that derives it. `docs/authorization-slice.md` carried three such rows, and
  their `co` column said 0 where the tree says 1: right when typed, wrong within
  the week, and the sentence rule cannot see it because the STATUS half stayed
  true.

What this row does not do, measured rather than guessed — an independent review
drove 23 spellings and broke the first version with plain English before it
needed a trick one:

* it does not read English. NEGATION and TENSE are invisible: "`SEC-FIDO-001` is
  not BOUNDED" and "`SEC-FIDO-007` is no longer MODELLED-ONLY" are false claims
  using the registry's own word about the right id, and both pass — and worse,
  both COUNT as held copies, so [`CLAIM_FLOOR`] is satisfiable by lies. No
  scanner of a natural language closes that;
* the vocabulary is CASE-SENSITIVE, so a lower-case `proven` in prose stays
  prose. That is a trade taken on a measurement: case-folding reports 45
  refusals over this corpus and almost every one is an ordinary word
  ("measured", "co-refuted");
* `_` is not stripped as emphasis, because stripping it turns
  `scripts/evidence_gate.py` into `evidencegate.py` and un-exempts all three
  generated pages. `PRO_VEN_` is therefore still a bypass, and this is the whole
  of what that trade costs;
* the transcribed-row rule catches the PIPE-TABLE layout and five others walk
  past it: an HTML `<table>`, the numbers on the next line, `mut 1 | co 0`,
  `45cfg | 11mut`, and the status moved to a header row. It catches the layout
  the author happened to use, not the copy;
* the corpus is markdown. A P0-family claim in a Rust doc comment
  (`store_meta_kani.rs` carries one, true today) is outside it.

What it does is make the WORDS the registry owns unusable as a lie about a row
that registry holds, in the shapes above.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = pathlib.Path("assurance/properties.toml")

#: A registered property id, in the three shapes the registry uses:
#: `SEC-FIDO-001`, the clause rows `SEC-FIDO-006A`, and the liveness rows
#: `SEC-FIDO-L01` — which a pattern anchored on a digit misses, and a test over
#: the registry is what caught that. Narrow on purpose otherwise:
#: `TM-HOST-GATES` and `PLAT-TOOL-004` are other registries' ids and other
#: rules' business.
ID = re.compile(r"\bSEC-[A-Z]+-[A-Z]?\d+[A-C]?\b")

#: The evidence vocabulary a published sentence may put beside an id. The three
#: the registry actually uses are held against this tuple by a CASE, not by
#: [`vocabulary`], which returns it verbatim — a reviewer read the first version
#: of this comment as a claim the function derives them, and it does not; the
#: rest are §4.2's
#: working classes plus the one §4.3 governs. `PROVEN` is here precisely BECAUSE
#: no row holds it: a word that is no id's status is refused of every id, which
#: is what makes the measured README sentence fall.
#:
#: Longest first, so `PROVEN-SOURCE` is never read as `PROVEN` with a suffix.
CLASSES = (
    "PROVEN-SOURCE",
    "BOUNDED-SOURCE",
    "MEASURED-PLATFORM",
    "BINARY-CHECKED",
    "MODEL-CHECKED",
    "MODELLED-ONLY",
    "ACCEPTED-RISK",
    "TRACE-LINKED",
    "CO-REFUTED",
    "MEASURED",
    "BOUNDED",
    "PROVEN",
)

#: The window: a PARAGRAPH. It was a sentence for one revision and that is how a
#: reviewer broke it in one line — a sentence beginning at column 0 saw only its
#: own line, so "`SEC-FIDO-001` is the authorization property.\nIt is PROVEN on
#: hardware." passed while the same words on one line were refused. Measured, this
#: corpus is hard-wrapped: 14 978 of 29 403 prose lines are 50-95 columns, so
#: whether a false claim was caught depended on where the author's editor wrapped.
PARAGRAPH = re.compile(r"\n\s*\n")

#: Registered prose that uses the vocabulary as VOCABULARY. A paragraph
#: explaining the status ladder — "a Kani harness names it -> BOUNDED; anything
#: else -> MODELLED-ONLY" — is not a claim about the id that happens to be
#: nearest, and no distance threshold separates the two: measured over this
#: corpus, true copies sit at 4..1128 characters from their id and false ones at
#: 59..1163, which overlap. So they are registered by the fragment carrying them,
#: each with a reason, and a fragment that stops occurring exactly once is a
#: finding — the shape `run_count_gate.SCOPED` already uses.
SCOPED = {
    (
        "CHANGELOG.md",
        "No\n  configuration names it → `ACCEPTED-RISK`; a Kani harness names it →"
        " `BOUNDED`;\n  anything else → `MODELLED-ONLY`. All **59** rows rebuild"
        " exactly.",
    ): "the status ladder's own derivation, quoted; the words are its VALUES and"
    " the nearest id is an example being classified, not a row being claimed",
    (
        "CHANGELOG.md",
        "the harnesses are named so that they stay: `assurance_gate` forces `BOUNDED`",
    ): "prose about what the gate DOES with the word — the sentence's subject is"
    " the naming rule, not the property beside it",
    (
        "docs/store-refinement.md",
        "`assurance_gate` FORCES `BOUNDED` from a harness function name",
    ): "the same sentence one page over, and the same reading",
    (
        "docs/store-refinement.md",
        "`BOUNDED` there\n  would be a scalar going up while the domain went quietly down.",
    ): "a hypothetical the page argues AGAINST, which is the opposite of a claim"
    " that the row holds it",
}

#: `<!-- name:start -->` … `<!-- name:end -->`, the shape EVERY generator in this
#: tree marks its regions with. Derived from the shape rather than from a list of
#: generators: a list is one more roster to keep, and this row would then read a
#: new generator's output as hand-written prose.
REGION = re.compile(r"<!--\s*([a-z0-9-]+):start\s*-->")

#: A page some generator writes whole, said in its own first lines. Same reason:
#: the header is the page's own claim about itself, and a roster here would go
#: stale against it.
GENERATED_WHOLE = re.compile(r"Generated by scripts/[a-z_]+\.py")

#: A bare integer, for the transcribed-row rule, counted over the line with its
#: IDS BLANKED: the `007` of `SEC-FIDO-007` is a bare integer by every pattern,
#: and counting it took "`SEC-FIDO-007` is MODELLED-ONLY and 2 of 3
#: configurations check it" to three. Three, because the derived vector's
#: narrowest row still carries `cfgs`, `mut` and `co`.
NUMBER = re.compile(r"(?<![\w.])\d+(?![\w.])")
ROW_NUMBERS = 3

#: True copies the sweep must still find. A PARAMETER of [`audit`] and not a
#: global a case patches down, so the shipped value is the one every case runs
#: against — `SCAN_FLOOR` in `run_count_gate.py` shipped the other way and its own
#: commit message says the shipped 8 was therefore never checked.
#:
#: Under the measured 11. It is a floor on the SCANNER, not on the prose: a
#: masking bug, an empty corpus or a vocabulary that stopped matching all read as
#: "no claims found", which is indistinguishable from a clean tree. The first
#: version said "under the measured 4" and the tree measured 5 the day it shipped
#: — a number this rule could not see, because `scripts/` is not markdown.
CLAIM_FLOOR = 6

#: Pages the corpus must still hold, for the same reason one layer out: if the
#: listing ever answers short, every rule here passes over nothing. Under the
#: measured 66 hand-written of 69 tracked markdown — and the number is the one
#: the floor is COMPARED against, which the first version got wrong: it said
#: "under the measured 323" and 323 was the pre-exemption count of a different
#: corpus entirely.
CORPUS_FLOOR = 50

#: The sentence the Definition of done requires the project to keep saying, and
#: the ONE spelling this rule reads. Four pages say it today in FOUR spellings —
#: "**not** make RS-Key formally verified", "RS-Key is not formally verified",
#: and two more — so nothing could check it: a disclaimer with four spellings is
#: a disclaimer no rule can hold, and deleting all four left every gate green.
#: Emphasis is stripped before matching, so the bolded form counts and a fifth
#: spelling does not.
DISCLAIMER = "rs-key is not formally verified"

#: The paragraph the three generated pages emit, kept HERE and imported by them.
#: Three copies of a sentence whose whole purpose is that it cannot be quietly
#: dropped would be three places to drop it from, which is the defect one
#: directory over. It names where the residual risks are, because the Definition
#: of done asks for them BESIDE the claims and no generated page linked either
#: page before this.
DISCLAIMER_PARAGRAPH = (
    "**RS-Key is not formally verified.** This page is generated from the"
    " registry and reports what evidence exists, not that a whole-system theorem"
    " does. The Definition of done keeps this sentence a requirement until one"
    " exists, and `scripts/claims_gate.py` holds every page naming three or more"
    " registered properties to it. What is out of scope and what is accepted:"
    " [limitations](limitations.md) and the [threat model](threat-model.md)."
)

#: How many distinct registered ids make a page one a reader takes an assurance
#: claim FROM. Three, and MARKDOWN only: `.tla`, `.toml` and `.sh` name ids as
#: data and are not where anyone reads a summary. Measured, seven `.md` pages
#: clear it — `docs/assurance-vector.md` and `formal/README.md` at 59 each,
#: `docs/assurance-matrix.md` at 40, `docs/platform-assumptions.md` at 34 — and
#: exactly ONE of the eight carried the sentence.
DISCLAIMER_IDS = 3

#: Pages that must carry it, floored so the derivation going blind is a finding
#: rather than a clean run. Under the measured 8, and a PARAMETER of [`audit`]
#: like its two neighbours — it shipped as a global for one revision and its
#: mutation table reported the mutant SURVIVING, because a case can only reach a
#: global by monkeypatching it, which is the shape `SCAN_FLOOR` shipped with.
DISCLAIMER_FLOOR = 6


def vocabulary(root: pathlib.Path) -> tuple[dict, tuple]:
    """({id: status}, the words a claim may use).

    The statuses come from the registry rather than from [`CLASSES`], and the
    check that [`CLASSES`] still contains them is a test's — a status added to the
    registry and not here would otherwise be a word this row silently stops
    reading, which is the failure the whole file is about.
    """
    registry = tomllib.loads((root / REGISTRY).read_text(encoding="utf-8"))
    status = {
        str(row.get("id")): str(row.get("status"))
        for row in registry.get("property", [])
    }
    return status, CLASSES


def mask_regions(text: str) -> str:
    """`text` with every generated region blanked, newlines kept so a reported
    line number still points where it says."""
    out = text
    for found in REGION.finditer(text):
        end = f"<!-- {found.group(1)}:end -->"
        stop = text.find(end, found.start())
        if stop != -1:
            chunk = text[found.start() : stop + len(end)]
            out = out.replace(chunk, "\n" * chunk.count("\n"), 1)
    return out


def generated_pages(root: pathlib.Path) -> dict[str, str]:
    """{page: the header that exempts it} — DERIVED from the generators.

    Not the phrase in the page's own first bytes, which is what the first version
    read and which nothing checked. Driven on that version: a hand-written page
    exempted itself with `Generated by scripts/no_such_gate.py`, with a REAL
    generator's name over a page it does not write, and with the phrase in
    ordinary prose rather than in a comment — three passes at exit 0. Each
    generator names the file it writes in an `ARTIFACT` constant and its own
    header in `GENERATED_BY`; this is that pair, so a page is exempt only where
    the script that claims it really writes it.
    """
    out = {}
    for name in sorted((root / "scripts").glob("*_gate.py")):
        if name.name.startswith("test_"):
            continue
        source = name.read_text(errors="replace")
        page = re.search(r'^ARTIFACT = pathlib\.Path\("([^"]+)"\)', source, re.M)
        header = re.search(r'^GENERATED_BY = "([^"]+)"', source, re.M)
        if page and header:
            out[page.group(1)] = header.group(1)
    return out


def markdown(root: pathlib.Path) -> list[str]:
    """Every tracked `*.md`, which is the corpus a reader takes a claim from.

    `run_count_gate.scanned` was the first corpus and it is the WRONG one here:
    it is `docs/`, `formal/`, `.github/` plus the root, because a run-count is
    published there. Measured, that left 1018 tracked files out — every nested
    README, and `CHANGELOG.md`, which carried "the other three store properties
    stay MODELLED-ONLY" over a family of six. The run-count carve-out's own
    reason does not transfer: "an entry saying what a run cost at 0.4.10 stays
    0.4.10's" is true of a cost and false of a status.
    """
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.md"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return sorted(rel for rel in listing.split("\0") if rel and (root / rel).is_file())


def normalise(text: str) -> str:
    """`text` as a reader sees it, for the two rules that read words.

    Markdown emphasis, a zero-width space and the non-ASCII hyphens all render
    identically to what they hide, and each of them walked a literal `PROVEN`
    past the first version: `PRO**VEN**`, `PRO\u200bVEN`, `SEC\u2011FIDO\u2011001`.
    A hyphen at a line end is joined for the same reason. Case is NOT folded, and
    that is measured rather than lazy: over this corpus a case-insensitive
    vocabulary reports 45 refusals, and almost every one is an ordinary word —
    "measured", "co-refuted" — so the rule reads the SHOUTED forms the registry
    uses and a lower-case `proven` in prose stays prose.
    """
    text = text.replace("\u200b", "").replace("\u2011", "-").replace("\u2010", "-")
    text = re.sub(r"-\n[ \t]*", "-", text)
    # `*` and a backtick only. `_` is markdown emphasis too and stripping it was
    # measured to be worse than the hole it closes: it turns
    # `Generated by scripts/evidence_gate.py` into `evidencegate.py`, which
    # un-exempted all three generated pages at once. A `PRO_VEN_` bypass is left
    # open and said so here rather than paid for that way.
    return re.sub(r"[*`]", "", text)


def corpus(root: pathlib.Path) -> list[tuple[str, str]]:
    """(path, hand-written text) for every markdown a claim can be typed in."""
    exempt = generated_pages(root)
    out = []
    for rel in markdown(root):
        text = normalise((root / rel).read_text(errors="replace"))
        if rel in exempt and exempt[rel] in text[:600]:
            continue
        out.append((rel, mask_regions(text)))
    return out


def published(root: pathlib.Path) -> list[tuple[str, str]]:
    """(path, WHOLE text) for every markdown, generated pages included.

    The disclaimer rule reads this and not [`corpus`]: the three pages carrying
    the most registered ids are generated whole, so a rule over the hand-written
    residue would ask the sentence of everyone except the pages a reader most
    likely reads. Their generators emit it now.
    """
    return [
        (rel, normalise((root / rel).read_text(errors="replace")))
        for rel in markdown(root)
    ]


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def audit(
    root: pathlib.Path,
    claim_floor: int = CLAIM_FLOOR,
    corpus_floor: int = CORPUS_FLOOR,
    disclaimer_floor: int = DISCLAIMER_FLOOR,
) -> tuple[list[str], str]:
    root = pathlib.Path(root)
    findings: list[str] = []
    status, words = vocabulary(root)
    vocab = re.compile(r"\b(" + "|".join(re.escape(w) for w in words) + r")\b")
    pages = corpus(root)
    if len(pages) < corpus_floor:
        findings.append(
            f"the scan reached {len(pages)} page(s), under the floor of"
            f" {corpus_floor} — a corpus that shrank is a rule that stopped"
            " looking, and it reads exactly like a tree with nothing to find"
        )

    scoped = {(rel, frag): 0 for rel, frag in SCOPED}
    held = rows = 0
    for rel, text in pages:
        exempt = []
        for (page, fragment) in SCOPED:
            if page != rel:
                continue
            # Normalised the same way the text is, so a fragment may be quoted
            # from the page as written rather than as this rule reads it.
            needle = normalise(fragment)
            at = text.find(needle)
            if at != -1:
                scoped[(page, fragment)] = text.count(needle)
                exempt.append((at, at + len(needle)))
        cursor = 0
        for chunk in PARAGRAPH.split(text):
            base = text.find(chunk, cursor)
            cursor = base + len(chunk) if base != -1 else cursor
            spans = [
                (m.start(), m.end(), m.group(0))
                for m in ID.finditer(chunk)
                if m.group(0) in status
            ]
            if not spans:
                continue
            for word in vocab.finditer(chunk):
                where = max(base, 0) + word.start()
                if any(a <= where < b for a, b in exempt):
                    continue
                # The nearest id that PRECEDES the word, and the nearest overall
                # only when none does. Not the union over the paragraph: that let
                # two ids lend each other their statuses — "`SEC-FIDO-001` is
                # MODELLED-ONLY and `SEC-STORE-005` is BOUNDED" has both halves
                # backwards and scored TWO true copies. And not the nearest in
                # either direction: a LIST after a claim steals it, measured on
                # "`SEC-STORE-002` rises to BOUNDED. `SEC-STORE-001`, … stay
                # MODELLED-ONLY", where the first name of the list is two
                # characters from a word that is about the id before it. English
                # puts the subject first; the fallback covers a word in a heading
                # over a body that names the id.
                before = [s for s in spans if s[1] <= word.start()]
                near = min(
                    before or spans,
                    key=lambda s: min(abs(s[0] - word.end()), abs(word.start() - s[1])),
                )[2]
                if word.group(0) == status[near]:
                    held += 1
                    continue
                findings.append(
                    f"{rel}:{line_of(text, where)}: says `{word.group(0)}` beside"
                    f" {near}, whose registered status is {status[near]} — a"
                    " hand-written status is a copy, and this one is not a copy of"
                    " anything"
                )
        for number, line in enumerate(text.splitlines(), 1):
            if not (ID.search(line) and vocab.search(line)):
                continue
            bare = NUMBER.findall(ID.sub(" ", line))
            if len(bare) < ROW_NUMBERS:
                continue
            rows += 1
            findings.append(
                f"{rel}:{number}: an id, a status and {len(bare)}"
                " bare numbers on one line is a transcribed row of the derived"
                " evidence vector — it belongs to the generator that derives it,"
                " because the status half can stay true while a column rots"
            )

    owed = 0
    for rel, text in published(root):
        if not rel.endswith(".md"):
            continue
        if len({i for i in ID.findall(text) if i in status}) < DISCLAIMER_IDS:
            continue
        owed += 1
        # Emphasis stripped, so `**not**` counts; nothing else is normalised,
        # because a rule that accepts any paraphrase accepts the paraphrase that
        # drops the word "not".
        if DISCLAIMER not in re.sub(r"[*_`]", "", text).lower():
            findings.append(
                f"{rel}: names {len({i for i in ID.findall(text) if i in status})}"
                f" registered properties and does not say {DISCLAIMER!r} — the"
                " Definition of done keeps that sentence a requirement, and a page"
                " a reader takes a status from is where it has to be"
            )
    if owed < disclaimer_floor:
        findings.append(
            f"{owed} page(s) owe the disclaimer, under the floor of"
            f" {disclaimer_floor} — the derivation that finds which pages make a"
            " claim went blind, and no page owing it reads as every page having it"
        )

    for (page, fragment), seen in sorted(scoped.items()):
        if seen != 1:
            findings.append(
                f"{page}: the registered fragment {fragment.splitlines()[0][:48]!r}"
                f" occurs {seen} time(s) — an exemption that stopped matching"
                " exempts nothing and hides whatever moved into its place, and a"
                " second copy is the rot this rule is about wearing an exemption"
            )

    if held < claim_floor:
        findings.append(
            f"the scan matched {held} true status copy/copies, under the floor of"
            f" {claim_floor} — the floor is on the SCANNER: a masking bug or a"
            " vocabulary that stopped matching reads as a tree with no claims in it"
        )
    summary = (
        f"claims-gate: ok — {len(pages)} published page(s), {held} hand-written"
        f" status(es) held against the registry, {rows} transcribed row(s),"
        f" {owed} page(s) carrying the disclaimer"
    )
    return findings, summary


def main() -> int:
    findings, summary = audit(ROOT)
    if findings:
        print("claims-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "\nA published status is a claim, and the registry is the only place"
            "\nthis tree decides one. Generate the sentence, or make it true.",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
