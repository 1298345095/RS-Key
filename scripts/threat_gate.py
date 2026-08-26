#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold each P0-family property against the threat it is against.

`docs/threat-model.md` is the root of the evidence chain every claim in
`assurance/properties.toml` hangs from, and 33 rows cited it by the file name
alone. "Against the threat model" names no threat: a property with no clause
behind it is either mis-scoped or unnecessary, and neither was visible — while a
stated threat with no property behind it was not visible either.

Three rules, and the third is the one the file exists for:

* the clause SET is derived from the markdown — every heading and every list
  item — and `assurance/threat_clauses.toml` must name each one exactly once. A
  new bullet is then a clause nobody classified, and a clause whose locked first
  line moved or was reworded is a citation gone stale, both red. The lock is
  content, not a line number: text inserted above a clause does not rot it.
* every P0-family property (the `p0-launch` + `p0b` tranches of
  `assurance/configurations.toml`, which is where "P0 family" is defined once)
  cites at least one `defence` clause as `docs/threat-model.md#ID`. The bare
  `docs/threat-model.md` spelling no longer satisfies it — naming the file is
  what this row was written to stop.
* a property with no clause is a FINDING, not a blank, and says which of the two
  it is: `missing-clause` (the page does not state a threat this tree defends
  against) or `defends-nothing`. Exactly one of the two lists holds each P0
  row — an `[[untraced]]` entry for a property that has since gained a clause is
  a stale exemption and is refused, the way `assurance_gate.py` refuses one for a
  configuration that has gone.

What it cannot say, like its siblings: whether a mapping is RIGHT. `why` is prose
and nothing reads it for truth. What it keeps honest is that the mapping is
total in both directions, that a cited clause is really on the page, and that a
row with no threat behind it says so out loud instead of reading as traced.

The unserved `defence` clauses are printed rather than refused: `firmware-flavor`
sections like anti-rollback or supply chain are real defences that no *state*
property is about, and refusing them would push a false mapping into the
registry. They are the other half of the finding and belong in front of a reader,
not in an exit code.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

import matrix_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

DOC = pathlib.Path("docs/threat-model.md")
CLAUSES = pathlib.Path("assurance/threat_clauses.toml")
#: One definition of "the registry" and one of "the P0 family", both borrowed
#: rather than restated: a second copy of the tranche lists is the failure the
#: header of `assurance/properties.toml` is about.
REGISTRY = matrix_gate.REGISTRY
LEDGER = matrix_gate.LEDGER

#: A clause reference inside a `source` entry. The fragment is a registry id, not
#: a rendered anchor — `docs/threat-model.md` carries no HTML anchors.
REF = re.compile(rf"^{re.escape(str(DOC))}#([A-Z][A-Z0-9-]*)$")
#: An in-tree path used as a source, with the optional ` — section` tail the
#: registry already writes for `formal/README.md`. Checked for existence, so the
#: day stage 9C/9D/10 cite `docs/ct-audit.md`, `docs/unsafe.md` or
#: `docs/limitations.md` the citation is held to a file that is really there.
PATH_SOURCE = re.compile(r"^([A-Za-z0-9_./-]+\.(?:md|toml|tla|rs|py|sh))(?: — .*)?$")

KINDS = ("defence", "context")
VERDICTS = ("missing-clause", "defends-nothing")

#: Floors AT today's counts, in the shape the rest of `scripts/` uses them: a
#: derivation that finds nothing satisfies every rule below over an empty roster.
#: 45 clauses is the page as it stands and 40 the P0 family as the tranches stand;
#: shrinking either for real is a deliberate edit here, in the same diff.
FLOOR_CLAUSES = 45
FLOOR_P0 = 40
#: The untraced list is a finding register, and a finding register that grows
#: silently is a hatch. Raising this is the deliberate admission that another
#: property has no threat behind it.
CEILING_UNTRACED = 7
#: A `why` shorter than this is a shrug with a verdict column. Same floor and
#: same reason as `matrix_gate.FLOOR_WORDS`, borrowed rather than re-picked.
FLOOR_WORDS = matrix_gate.FLOOR_WORDS


#: A fence, in both of CommonMark's spellings and at any indent. Three of them
#: is the minimum, and a longer run is the same fence, so `startswith` after the
#: indent is the whole rule.
FENCE = re.compile(r"^\s*(?:```|~~~)")
#: A heading at ANY level, not the two this page happens to use: an `####` under
#: a section would otherwise be a clause the derivation cannot see, which is the
#: only direction that fails silently. Over-detection reddens instead.
HEADING = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
#: A list item in every marker CommonMark takes. The page writes `-` throughout;
#: `*`, `+` and an ordered item are the same clause written by someone else.
ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
#: A setext underline directly under text — a heading this derivation cannot see.
#: The "previous line is prose" test keeps an ordinary thematic break (blank
#: line, `---`, blank line) out of it. `-+` and not `-{3,}`: CommonMark makes a
#: SINGLE `-` an H2, and the first draft of this line demanded three, so the two
#: shortest spellings of the thing it refuses were the two it could not see.
SETEXT = re.compile(r"^\s*(?:=+|-+)\s*$")
#: Shapes that can carry a clause and that nothing above can read: a blockquote
#: callout, a table row, an HTML list. Refused rather than missed, for the reason
#: the whole file exists — a clause the derivation cannot see is the one
#: direction that fails green. A table is the likeliest: this repo's other docs
#: enumerate exactly this kind of thing in one.
UNREADABLE = re.compile(r"^\s*(?:>|\||</?(?:ul|ol|li|table|tr|dl|dt|dd)\b)")
#: A clause id, in the one spelling `source` can cite (`REF` takes `[A-Z]…`), so
#: a `TM-Host-Fuzz` is refused here rather than surfacing later as a message that
#: blames the citing row's spelling.
CLAUSE_ID = re.compile(r"TM-[A-Z0-9]+(?:-[A-Z0-9]+)*")


def clause_units(text: str, problems: list[str] | None = None) -> list[tuple[int, str, str]]:
    """(line, enclosing section, first line) for every addressable clause.

    A heading or a list item, which is the whole structure this page has. Fenced
    blocks are skipped: the seed-backup mermaid diagram carries `-` lines that
    are arrows, not clauses. Lines are `rstrip`ped, so trailing whitespace is not
    a clause moving.
    """
    units: list[tuple[int, str, str]] = []
    section, fenced, previous = "", False, ""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if FENCE.match(line):
            fenced = not fenced
            previous = line
            continue
        if fenced:
            previous = line
            continue
        heading = HEADING.match(line)
        if heading:
            section = heading.group(2)
            units.append((number, section, line))
        elif ITEM.match(line):
            units.append((number, section, line))
        elif problems is None:
            pass
        elif SETEXT.match(line) and previous.strip():
            problems.append(
                f"{DOC}:{number}: a setext heading (or a thematic break under"
                " text) — this derivation reads `#` headings only, so a clause"
                " written that way would be invisible to it"
            )
        elif UNREADABLE.match(line):
            problems.append(
                f"{DOC}:{number}: a blockquote, table row or HTML list — a clause"
                " in one is invisible to this derivation. Write it as a `#`"
                f" heading or a `-` item: {line.strip()[:40]!r}"
            )
        previous = line
    return units


def load(root: pathlib.Path, path: pathlib.Path) -> dict:
    return tomllib.loads((root / path).read_text(encoding="utf-8"))


def p0_family(root: pathlib.Path) -> list[str]:
    """The P0-family ids, in registry order, from the tranche lists."""
    doc = load(root, LEDGER).get("tranche", {})
    tranche = {pid: name for name in matrix_gate.TRANCHES for pid in doc.get(name, [])}
    ids = [entry.get("id") for entry in load(root, REGISTRY).get("property", [])]
    return [pid for pid in ids if tranche.get(pid) in matrix_gate.ROW_TRANCHES]


def check_clauses(root: pathlib.Path, problems: list[str]) -> dict[str, dict]:
    """The roster, held against the page in both directions."""
    units = clause_units((root / DOC).read_text(encoding="utf-8"), problems)
    by_line: dict[str, list[int]] = {}
    for number, _section, line in units:
        by_line.setdefault(line, []).append(number)
    for line, numbers in sorted(by_line.items()):
        if len(numbers) > 1:
            problems.append(
                f"{DOC}: lines {numbers} read identically — two clauses this"
                f" roster cannot address apart: {line.strip()[:60]!r}"
            )
    if len(units) < FLOOR_CLAUSES:
        problems.append(
            f"{DOC}: derived {len(units)} clause(s), under the floor of"
            f" {FLOOR_CLAUSES} — the page shrank, or the derivation stopped"
            " seeing it. Shrink the floor here in the same diff"
        )

    entries = load(root, CLAUSES).get("clause", [])
    clauses: dict[str, dict] = {}
    for index, entry in enumerate(entries, 1):
        cid, where = entry.get("id"), entry.get("where")
        if not cid or not where:
            problems.append(f"{CLAUSES}: clause #{index} has no id or no `where`")
            continue
        if not CLAUSE_ID.fullmatch(cid):
            problems.append(
                f"{CLAUSES}: {cid!r} is not a clause id — `source` can only cite"
                " `TM-` and upper case, so any other spelling is uncitable"
            )
            continue
        if cid in clauses:
            problems.append(f"{CLAUSES}: duplicate clause id {cid}")
            continue
        if twin := next((c for c, e in clauses.items() if e["where"] == where), None):
            problems.append(
                f"{cid} and {twin} claim the same clause of {DOC} — one unit, one"
                " entry, or the page is classified twice and can be classified"
                " two ways at once"
            )
            continue
        if entry.get("kind") not in KINDS:
            problems.append(
                f"{cid}: kind {entry.get('kind')!r} is not one of {list(KINDS)}"
            )
        if entry.get("kind") == "context" and len(entry.get("why", "").split()) < FLOOR_WORDS:
            problems.append(
                f"{cid}: `context` says no property can serve this clause, and under"
                f" {FLOOR_WORDS} words that is an assertion with no argument"
            )
        if where not in by_line:
            problems.append(
                f"{cid}: `where` is not a clause of {DOC} any more — it was"
                f" reworded, deleted or re-indented: {where.strip()[:60]!r}"
            )
        clauses[cid] = entry

    claimed = {entry["where"] for entry in clauses.values()}
    for number, section, line in units:
        if line not in claimed:
            problems.append(
                f"{DOC}:{number}: a clause nobody classified — add it to {CLAUSES}"
                f" as `defence` or `context` (under {section!r}): {line.strip()[:60]!r}"
            )
    return clauses


def check_sources(
    root: pathlib.Path,
    clauses: dict[str, dict],
    family: list[str],
    problems: list[str],
) -> dict[str, list[str]]:
    """property id -> the clauses it cites, with every citation validated."""
    cited: dict[str, list[str]] = {}
    p0 = set(family)
    for entry in load(root, REGISTRY).get("property", []):
        pid = entry.get("id", "?")
        for source in entry.get("source", []):
            ref = REF.match(source)
            if ref:
                cid = ref.group(1)
                if cid not in clauses:
                    problems.append(
                        f"{pid}: source names {cid}, which is no clause of {CLAUSES}"
                    )
                elif clauses[cid].get("kind") != "defence":
                    problems.append(
                        f"{pid}: source names {cid}, which is"
                        f" {clauses[cid].get('kind')!r} and not a `defence` — assets,"
                        " an out-of-scope declaration or a process is not a threat a"
                        " property can be against"
                    )
                elif cid not in cited.setdefault(pid, []):
                    cited[pid].append(cid)
                continue
            if source == str(DOC):
                if pid in p0:
                    problems.append(
                        f"{pid}: source says {DOC} and nothing more — say WHICH"
                        f" clause, as `{DOC}#TM-…`"
                    )
                continue
            if DOC.name in source:
                # Anything else naming the page: `#tm-host-gates`, `./docs/…`,
                # a trailing slash. Each falls through every rule above while
                # LOOKING traced, which is the one outcome worth refusing.
                problems.append(
                    f"{pid}: {source!r} names the threat model in a spelling this"
                    f" row cannot resolve — write it as `{DOC}#TM-…`"
                )
                continue
            path = PATH_SOURCE.match(source)
            if path and not (root / path.group(1)).exists():
                problems.append(
                    f"{pid}: source cites {path.group(1)}, which is not in the tree"
                )
    return cited


def check_untraced(
    root: pathlib.Path,
    cited: dict[str, list[str]],
    family: list[str],
    problems: list[str],
) -> dict[str, dict]:
    entries = load(root, CLAUSES).get("untraced", [])
    untraced: dict[str, dict] = {}
    for index, entry in enumerate(entries, 1):
        pid = entry.get("id")
        if not pid:
            problems.append(f"{CLAUSES}: untraced #{index} has no id")
            continue
        if pid in untraced:
            problems.append(f"{CLAUSES}: {pid} is untraced twice")
            continue
        untraced[pid] = entry
        if pid not in family:
            problems.append(
                f"{pid}: untraced, but it is not a P0-family property — this list is"
                " the P0 family's finding register, not a place to park a row"
            )
        if entry.get("verdict") not in VERDICTS:
            problems.append(
                f"{pid}: verdict {entry.get('verdict')!r} is not one of"
                f" {list(VERDICTS)} — a row with no threat behind it is one of"
                " exactly those two things"
            )
        if len(entry.get("why", "").split()) < FLOOR_WORDS:
            problems.append(
                f"{pid}: untraced with a `why` under {FLOOR_WORDS} words — the"
                " finding IS the why, and `TODO` is not one"
            )
        if pid in cited:
            problems.append(
                f"{pid}: untraced and citing {', '.join(cited[pid])} — a stale"
                " exemption reads as a finding that is still open"
            )
    if len(untraced) > CEILING_UNTRACED:
        problems.append(
            f"{len(untraced)} untraced P0-family propert(ies), over the ceiling of"
            f" {CEILING_UNTRACED} — another property with no threat behind it is a"
            " deliberate admission; raise the ceiling here in the same diff"
        )
    return untraced


def audit(root) -> tuple[list[str], list[str], str]:
    """(problems, the report a reader needs, one-line summary) for this checkout."""
    root = pathlib.Path(root)
    problems: list[str] = []
    # A missing or unparseable input is a finding with a sentence, not a
    # traceback: the row goes red either way, and only one of the two says what
    # to do about it.
    for path in (DOC, CLAUSES, REGISTRY, LEDGER):
        if not (root / path).is_file():
            problems.append(f"{path} is missing — the mapping is unchecked")
            return problems, [], "threat-gate: nothing to check"
    for path in (CLAUSES, REGISTRY, LEDGER):
        try:
            load(root, path)
        except tomllib.TOMLDecodeError as error:
            problems.append(f"{path} cannot be read: {error}")
            return problems, [], "threat-gate: nothing to check"
    clauses = check_clauses(root, problems)
    family = p0_family(root)
    cited = check_sources(root, clauses, family, problems)
    if len(family) < FLOOR_P0:
        problems.append(
            f"{len(family)} P0-family propert(ies), under the floor of {FLOOR_P0} —"
            " the tranche lists shrank, and fewer rows owe a threat than when this"
            " floor was set. Shrink it here in the same diff"
        )
    untraced = check_untraced(root, cited, family, problems)
    for pid in family:
        if pid not in cited and pid not in untraced:
            problems.append(
                f"{pid}: no threat-model clause and no untraced verdict — name the"
                f" clause it serves as `{DOC}#TM-…`, or record in {CLAUSES} which of"
                f" {list(VERDICTS)} it is"
            )

    serves: dict[str, list[str]] = {}
    others: dict[str, list[str]] = {}
    for pid, ids in cited.items():
        for cid in ids:
            (serves if pid in family else others).setdefault(cid, []).append(pid)
    report = []
    for cid, entry in clauses.items():
        if entry.get("kind") != "defence":
            continue
        owners = serves.get(cid, [])
        # The outside-family owners are appended in BOTH branches: printing them
        # only when the P0 column is empty made a clause look thinner than it is,
        # and read as "answered only outside the family" when it was not.
        outside = f" (+ outside the P0 family: {', '.join(others[cid])})" if cid in others else ""
        rest = ", ".join(owners) if owners else "— no registered property"
        report.append(f"  {cid:<30} {len(owners):>2}  {rest}{outside}")
    for pid, entry in untraced.items():
        report.append(f"  {pid:<30}  -  untraced [{entry.get('verdict')}]")
    defences = [c for c in clauses.values() if c.get("kind") == "defence"]
    summary = (
        f"threat-gate: ok — {len(clauses)} clause(s) ({len(defences)} defence,"
        f" {len(clauses) - len(defences)} context), {len(family) - len(untraced)}"
        f" of {len(family)} P0-family properties traced,"
        f" {len(serves)} clause(s) served, {len(untraced)} untraced"
    )
    return problems, report, summary


def run(root: pathlib.Path) -> int:
    problems, report, summary = audit(root)
    for line in report:
        print(line)
    if problems:
        print(f"threat-gate: {len(problems)} finding(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main() -> int:
    if sys.argv[1:]:
        print("usage: threat_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
