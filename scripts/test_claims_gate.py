# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `claims_gate.py`.

The fixture is the SHIPPED corpus with one sentence appended, because the rule is
about what a person types into a real page and a synthetic tree would prove it
about prose nobody has to keep true. Every case here appends and asserts, or
reverts one rule and asserts the shipped tree goes red.
"""

import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import claims_gate  # noqa: E402

ROOT = claims_gate.ROOT
PAGE = "README.md"


@pytest.fixture
def tree(tmp_path):
    """A checkout carrying every page the corpus reads, plus the registry.

    Copied rather than synthesised, and `git init`ed because the corpus is
    `git ls-files`: a walk would descend into `target/` and into any agent
    worktree, which is the defect `deleter_gate` shipped with.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\0")
    for rel in listing:
        if not rel:
            continue
        source = ROOT / rel
        if not source.is_file():
            continue
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, target)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    # `run_count_gate.tracked` asks `git ls-files` for the CACHE, so a fixture
    # that only `init`s answers an empty corpus and every rule here passes over
    # nothing — measured, and it is the same "the scan found none" shape the
    # floors exist for.
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


def findings(root, **kwargs):
    return claims_gate.audit(root, **kwargs)[0]


def say(root, sentence, page=PAGE):
    path = root / page
    path.write_text(path.read_text() + "\n\n" + sentence + "\n")


def test_this_checkout_is_green():
    assert findings(ROOT) == []


def test_the_fixture_is_this_checkout(tree):
    assert findings(tree) == []


# The measured failure this row exists for: four false hand-written sentences,
# including this one in README.md, at EXIT=0 on all eight gates.
@pytest.mark.parametrize(
    "sentence",
    [
        "`SEC-FIDO-001` is PROVEN on hardware.",
        "The store slice leaves `SEC-STORE-005` BOUNDED today.",
        "`SEC-FIDO-007` is MEASURED on an RP2350 A4 board.",
        "`SEC-FIDO-002` is BINARY-CHECKED against the shipped ELF.",
        "We rate `SEC-STORE-001` PROVEN-SOURCE after the store slice.",
    ],
)
def test_a_status_no_row_holds_is_refused(tree, sentence):
    say(tree, sentence)
    reported = findings(tree)
    assert any("is a copy, and this one is not a copy of anything" in f for f in reported), reported


def test_a_true_status_is_kept(tree):
    """The half a `generated or refused` rule would have cost: a hand-written
    sentence that is TRUE does work no generated table does, and it stays."""
    say(tree, "`SEC-FIDO-001` is BOUNDED, which is why the slice could close.")
    assert findings(tree) == []


def test_a_true_status_stops_being_able_to_rot(tree):
    """And what it buys: the same sentence reddens when the registry moves."""
    say(tree, "`SEC-FIDO-001` is BOUNDED, which is why the slice could close.")
    registry = tree / claims_gate.REGISTRY
    registry.write_text(
        registry.read_text().replace(
            'id = "SEC-FIDO-001"\nname = "NoAuthorizationBypass"\nstatus = "BOUNDED"',
            'id = "SEC-FIDO-001"\nname = "NoAuthorizationBypass"\nstatus = "MODELLED-ONLY"',
            1,
        )
    )
    reported = findings(tree)
    assert any("SEC-FIDO-001" in f and "BOUNDED" in f for f in reported), reported


def test_a_transcribed_vector_row_is_refused(tree):
    """The rule the sentence rule cannot cover: the STATUS half stays true while a
    column rots. `docs/authorization-slice.md` carried three such rows and their
    `co` column said 0 where the tree says 1."""
    say(tree, "| `SEC-FIDO-007` | MODELLED-ONLY | 3 | 1 | 0 | 0 | 0 | 0 | 1 |")
    reported = findings(tree)
    assert any("transcribed row" in f for f in reported), reported


def test_two_numbers_beside_an_id_are_ordinary_prose(tree):
    """The floor under that rule, and why it is 3: `2 of 3 configurations` is a
    sentence, not a table."""
    say(tree, "`SEC-FIDO-007` is MODELLED-ONLY and 2 of 3 configurations check it.")
    assert findings(tree) == []


def test_a_generated_region_is_not_hand_written(tree):
    """Every generator in this tree marks its output; a rule that read those as
    prose would demand an author fix a table they may not edit."""
    say(
        tree,
        "<!-- claims-test:start -->\n"
        "| `SEC-FIDO-007` | PROVEN | 3 | 1 | 1 | 0 | 0 | 0 | 1 |\n"
        "<!-- claims-test:end -->",
    )
    assert findings(tree) == []


def test_a_wholly_generated_page_is_not_hand_written(tree):
    """`docs/assurance-vector.md` says so in its own first lines, and its numbers
    are already held by the generator that writes them."""
    (tree / "docs/assurance-vector.md").write_text(
        "<!-- Generated by scripts/evidence_gate.py --write -->\n"
        "| `SEC-FIDO-007` | PROVEN | 3 | 1 | 1 | 0 |\n"
    )
    assert findings(tree) == []


def test_an_unregistered_id_is_another_registry_s_business(tree):
    say(tree, "`PLAT-TOOL-004` is PROVEN and `TM-HOST-GATES` is MEASURED.")
    assert findings(tree) == []


def test_a_contrastive_status_must_name_its_subject(tree):
    """Words are scoped to the sentence, ids to the lines it touches — so a
    contrast whose second half names nobody is judged against the id beside it,
    and refused. Found on the shipped tree, not invented here: `formal/README.md`
    said "`SEC-STORE-002` is `BOUNDED`; the other three store properties stay
    `MODELLED-ONLY`" — and the family has six members, so the sentence was also
    wrong by two."""
    say(
        tree,
        "`SEC-FIDO-001` is BOUNDED and its store siblings are MODELLED-ONLY.",
    )
    reported = findings(tree)
    assert any("MODELLED-ONLY" in f and "SEC-FIDO-001" in f for f in reported), reported


def test_naming_the_subject_is_what_makes_the_contrast_legal(tree):
    """The repair the rule asks for, and the whole of it."""
    say(
        tree,
        "`SEC-FIDO-001` is BOUNDED and `SEC-STORE-005` is MODELLED-ONLY.",
    )
    assert findings(tree) == []


def test_a_table_row_is_not_one_sentence(tree):
    """A cell boundary ends the window: reading a whole row as one let a status in
    the third column excuse a word in the ninth."""
    say(tree, "| `SEC-FIDO-001` | BOUNDED | PROVEN-SOURCE |")
    reported = findings(tree)
    assert any("PROVEN-SOURCE" in f for f in reported), reported


def test_the_shipped_corpus_is_over_its_floor():
    assert len(claims_gate.corpus(ROOT)) >= claims_gate.CORPUS_FLOOR


def test_a_corpus_that_shrank_is_a_rule_that_stopped_looking(tree):
    reported = findings(tree, corpus_floor=10_000)
    assert any("under the floor of 10000" in f for f in reported), reported


def test_a_scanner_that_matches_nothing_is_not_a_clean_tree(tree):
    """The floor is on the SCANNER. Driven by asking for more true copies than the
    tree holds, which is what a masking bug or a dead vocabulary looks like."""
    reported = findings(tree, claim_floor=10_000)
    assert any("true status copy" in f for f in reported), reported


def test_every_registry_status_is_in_the_vocabulary():
    """A status added to the registry and not to `CLASSES` is a word this row
    silently stops reading — the exact failure the file is about, one level in."""
    registry = tomllib.loads((ROOT / claims_gate.REGISTRY).read_text(encoding="utf-8"))
    used = {str(row.get("status")) for row in registry.get("property", [])}
    assert used <= set(claims_gate.CLASSES), sorted(used - set(claims_gate.CLASSES))


def test_the_vocabulary_is_matched_longest_first():
    """`PROVEN-SOURCE` read as `PROVEN` plus a suffix would report the wrong word
    and, worse, would let `PROVEN-SOURCE` pass wherever `PROVEN` is legal."""
    order = list(claims_gate.CLASSES)
    for shorter in order:
        for longer in order:
            if longer != shorter and longer.startswith(shorter):
                assert order.index(longer) < order.index(shorter), (shorter, longer)


def test_the_id_pattern_reaches_the_clause_rows():
    """`SEC-FIDO-006A` is a registry row of its own, and a pattern that stopped at
    the digits would exempt three P0-launch ids."""
    registry = tomllib.loads((ROOT / claims_gate.REGISTRY).read_text(encoding="utf-8"))
    for row in registry.get("property", []):
        assert claims_gate.ID.fullmatch(str(row["id"])), row["id"]


def test_main_prints_a_summary_and_reports_findings(tree, capsys, monkeypatch):
    assert claims_gate.main() == 0
    assert capsys.readouterr().out.startswith("claims-gate: ok —")
    say(tree, "`SEC-FIDO-001` is PROVEN on hardware.")
    monkeypatch.setattr(claims_gate, "ROOT", tree)
    assert claims_gate.main() == 1
    assert "PROVEN" in capsys.readouterr().err


def test_the_page_that_carried_the_measured_rows_no_longer_does():
    """`docs/authorization-slice.md`'s three transcribed rows are the reason this
    file exists; a case asserts they are gone rather than merely that the row is
    green, because the row would also be green if the scan stopped reading."""
    page = (ROOT / "docs/authorization-slice.md").read_text()
    assert not re.search(r"\|\s*`SEC-FIDO-00\d`\s*\|\s*(BOUNDED|MODELLED-ONLY)\s*\|", page)
    assert "assurance-vector.md" in page


# ---- the sentence the Definition of done requires -----------------------------
#
# Four pages said it in FOUR spellings — "**not** make RS-Key formally verified",
# "RS-Key is not formally verified", and two more — so nothing could hold it, and
# deleting all four left every gate green. One spelling now, and the three pages
# carrying the MOST registered ids are generated, so their generators emit it.


def test_a_page_of_claims_without_the_disclaimer_is_refused(tree):
    page = tree / "docs/store-refinement.md"
    page.write_text(
        page.read_text().replace("**RS-Key is not formally verified**", "RS-Key is fine")
    )
    reported = findings(tree)
    assert any("does not say" in f and "store-refinement" in f for f in reported), reported


def test_the_bolded_spelling_counts(tree):
    """Emphasis is stripped before matching, so `**not**` reads the same. Nothing
    else is normalised: a rule that accepts any paraphrase accepts the paraphrase
    that drops the word "not"."""
    page = tree / "docs/store-refinement.md"
    page.write_text(
        page.read_text().replace(
            "**RS-Key is not formally verified**", "RS-Key **is not** formally verified"
        )
    )
    assert findings(tree) == []


def test_a_paraphrase_does_not_count(tree):
    page = tree / "docs/store-refinement.md"
    page.write_text(
        page.read_text().replace(
            "**RS-Key is not formally verified**",
            "this does not make RS-Key formally verified",
        )
    )
    reported = findings(tree)
    assert any("does not say" in f and "store-refinement" in f for f in reported), reported


def test_the_generated_pages_are_asked_too(tree):
    """The rule reads `published`, not `corpus`: the three pages naming the most
    ids are generated whole, and a rule over the hand-written residue would ask
    the sentence of everyone except the pages a reader most likely reads."""
    page = tree / "docs/assurance-vector.md"
    page.write_text(page.read_text().replace("RS-Key is not formally verified", "x"))
    reported = findings(tree)
    assert any("assurance-vector" in f and "does not say" in f for f in reported), reported


def test_a_page_naming_two_ids_is_not_a_summary(tree):
    say(tree, "`SEC-FIDO-001` and `SEC-FIDO-002` are both BOUNDED.", page="SECURITY.md")
    assert findings(tree) == []


def test_the_generators_emit_the_sentence_rather_than_a_hand_written_copy():
    """A copy in the page and not in the generator is one `--write` from gone —
    and three copies of the paragraph would be three places to drop it from, so
    the three generators emit the ONE in `claims_gate`."""
    for gate in ("evidence_gate.py", "matrix_gate.py", "platform_gate.py"):
        source = (ROOT / "scripts" / gate).read_text(encoding="utf-8")
        assert "claims_gate.DISCLAIMER_PARAGRAPH" in source, gate
        assert "RS-Key is not formally verified" not in source, f"{gate} keeps a copy"
    assert claims_gate.DISCLAIMER in claims_gate.DISCLAIMER_PARAGRAPH.lower()


def test_a_disclaimer_derivation_that_went_blind_is_not_a_clean_tree(tree):
    """The floor's own arm. It shipped as a global for one revision and this
    mutant SURVIVED — a case can only reach a global by patching it, which is
    patching the thing under test."""
    reported = findings(tree, disclaimer_floor=10_000)
    assert any("owe the disclaimer" in f for f in reported), reported


def test_the_disclaimer_floor_is_under_the_shipped_count():
    pages = [
        rel
        for rel, text in claims_gate.published(ROOT)
        if rel.endswith(".md")
        and len(set(claims_gate.ID.findall(text))) >= claims_gate.DISCLAIMER_IDS
    ]
    assert len(pages) >= claims_gate.DISCLAIMER_FLOOR, pages


# ---- what an independent review broke, and what closed it --------------------
#
# The first version scoped WORDS to a sentence and IDS to the lines that sentence
# touched, and took the union of the named ids' statuses. A reviewer broke the
# headline claim in one line, with plain English and no trick spelling, and the
# five cases of `test_a_status_no_row_holds_is_refused` went with it: re-typed the
# way a hard-wrapping author writes, all five passed. Measured on this corpus,
# 14 978 of 29 403 prose lines are 50-95 columns, so whether a false claim was
# caught depended on where the editor wrapped.


@pytest.mark.parametrize(
    "sentence",
    [
        "The authorization slice closes on `SEC-FIDO-001`.\nIt is PROVEN on hardware.",
        "The store slice leaves `SEC-STORE-005` where it was.\nIt is BOUNDED today.",
        "We re-ran `SEC-FIDO-007` on the bench.\nIt is MEASURED on an RP2350 A4 board.",
        "`SEC-FIDO-001` is the authorization property.\nIt is PROVEN on hardware.",
    ],
)
def test_a_line_break_does_not_hide_a_false_claim(tree, sentence):
    say(tree, sentence)
    reported = findings(tree)
    assert any("is not a copy of anything" in f for f in reported), reported


@pytest.mark.parametrize(
    "sentence",
    [
        "`SEC-FIDO-001` is MODELLED-ONLY and `SEC-STORE-005` is BOUNDED.",
        "`SEC-FIDO-001` and `SEC-FIDO-007` are both BOUNDED.",
    ],
)
def test_two_ids_do_not_lend_each_other_their_statuses(tree, sentence):
    """The union bug: A18 above has BOTH halves backwards and scored two `held`
    true copies. Attribution is to the nearest id that PRECEDES the word."""
    say(tree, sentence)
    reported = findings(tree)
    assert any("is not a copy of anything" in f for f in reported), reported


def test_a_list_after_a_claim_does_not_steal_it(tree):
    """And the reason attribution prefers a PRECEDING id: nearest-in-either-
    direction let the first name of a following list take a word that is about
    the id before it, two characters away."""
    say(
        tree,
        "`SEC-STORE-002` rises to BOUNDED. `SEC-STORE-001`, `SEC-STORE-003`,"
        " `SEC-STORE-004`, `SEC-STORE-005` and `SEC-STORE-006` stay MODELLED-ONLY."
        "\n\n**RS-Key is not formally verified.**",
        page="README.md",
    )
    assert findings(tree) == []


@pytest.mark.parametrize(
    "spelling",
    [
        "`SEC-FIDO-001` is PRO**VEN** on hardware.",
        "`SEC-FIDO-001` is PRO\u200bVEN on hardware.",
        "`SEC\u2011FIDO\u2011001` is PROVEN on hardware.",
        "`SEC-FIDO-001` is PROVEN on hard-\nware.",
    ],
)
def test_a_spelling_that_renders_the_same_reads_the_same(tree, spelling):
    """Emphasis, a zero-width space and the non-ASCII hyphens all render
    identically to what they hide, and each walked a literal `PROVEN` past the
    first version."""
    say(tree, spelling)
    reported = findings(tree)
    assert any("is not a copy of anything" in f for f in reported), reported


def test_the_corpus_reaches_the_changelog(tree):
    """`run_count_gate.scanned` was the first corpus and left 1018 tracked files
    out, `CHANGELOG.md` among them — and `CHANGELOG.md` carried "the other three
    store properties stay MODELLED-ONLY" over a family of six. The run-count
    carve-out's reason does not transfer: it is about a COST staying its
    release's, and a status was wrong the day it was typed."""
    say(tree, "`SEC-FIDO-001` is PROVEN on hardware.", page="CHANGELOG.md")
    reported = findings(tree)
    assert any("CHANGELOG.md" in f and "PROVEN" in f for f in reported), reported


@pytest.mark.parametrize(
    "header",
    [
        "<!-- Generated by scripts/no_such_gate.py --write -->",
        "<!-- Generated by scripts/evidence_gate.py --write -->",
        "The tables here are Generated by scripts/evidence_gate.py --write.",
    ],
)
def test_a_page_cannot_exempt_itself_by_saying_it_is_generated(tree, header):
    """Three passes at exit 0 on the first version: a script that does not exist,
    a real script over a page it does not write, and the phrase in ordinary
    prose. The exempt set is derived from each generator's own `ARTIFACT` and
    `GENERATED_BY` pair, so only the page a script really writes is exempt."""
    page = tree / "docs/threat-model.md"
    page.write_text(header + "\n" + page.read_text() + "\n\n`SEC-FIDO-001` is PROVEN.\n")
    reported = findings(tree)
    assert any("threat-model" in f and "PROVEN" in f for f in reported), reported


def test_the_generated_page_roster_is_the_generators_own():
    pages = claims_gate.generated_pages(ROOT)
    assert pages == {
        "docs/assurance-vector.md": "Generated by scripts/evidence_gate.py --write",
        "docs/assurance-matrix.md": "Generated by scripts/matrix_gate.py --write",
        "docs/platform-assumptions.md": "Generated by scripts/platform_gate.py --write",
    }, pages


def test_a_registered_exemption_that_stopped_matching_is_a_finding(tree):
    """An exemption exempts a FRAGMENT, and one that no longer occurs hides
    whatever moved into its place."""
    (page, fragment) = next(iter(claims_gate.SCOPED))
    target = tree / page
    target.write_text(target.read_text().replace(fragment, "gone", 1))
    reported = findings(tree)
    assert any("occurs 0 time(s)" in f for f in reported), reported


def test_a_registered_exemption_copied_twice_is_a_finding(tree):
    (page, fragment) = next(iter(claims_gate.SCOPED))
    target = tree / page
    target.write_text(target.read_text() + "\n\n" + fragment + "\n")
    reported = findings(tree)
    assert any("occurs 2 time(s)" in f for f in reported), reported


def test_every_registered_exemption_carries_a_reason():
    for key, reason in claims_gate.SCOPED.items():
        assert len(reason.split()) >= 8, key


@pytest.mark.parametrize(
    "floor", ["CLAIM_FLOOR", "CORPUS_FLOOR", "DISCLAIMER_FLOOR"]
)
def test_a_floor_tracks_the_tree_rather_than_sitting_at_zero(floor):
    """Lowering a floor was UNCAUGHT: the cases that drive each one pass their own
    value, so the constant they ship with binds nothing, and
    `test_the_shipped_corpus_is_over_its_floor` only gets easier as the floor
    drops. Held between half the measurement and the measurement, so 0 fails and
    an over-raise fails too."""
    measured = {
        "CLAIM_FLOOR": _measure_held(),
        "CORPUS_FLOOR": len(claims_gate.corpus(ROOT)),
        "DISCLAIMER_FLOOR": _measure_owed(),
    }[floor]
    value = getattr(claims_gate, floor)
    assert measured // 2 <= value <= measured, (floor, value, measured)


def _measure_held():
    summary = claims_gate.audit(ROOT)[1]
    return int(re.search(r"(\d+) hand-written", summary).group(1))


def _measure_owed():
    summary = claims_gate.audit(ROOT)[1]
    return int(re.search(r"(\d+) page\(s\) carrying", summary).group(1))
