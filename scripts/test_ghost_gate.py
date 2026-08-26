# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `ghost_gate.py`.

Every arm below is a DELETION performed on the real `RSKeySecurityState.tla`,
because the thing being falsified is a claim about that module and a synthetic
fixture would prove it about a different one. The module is written into the
fixture with its comments already stripped — the gate strips them anyway, and a
comment-free copy is what makes "delete this route and nothing else" a string
edit rather than a parser.

The two parametrized arms are the exit criterion this guard answers. One deletes
**every** route by which an action records the name; the other deletes exactly
**one** of them. A per-action name equality passes the second — `RegisterStart`,
`RegisterNdStart` and `AssertStart` each record twice, so the surviving route
keeps the name in the set and the row stays green over a half-deleted guard.
That is why routes are counted at all.
"""

import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ghost_gate  # noqa: E402

ROOT = ghost_gate.ROOT
DERIVED = ghost_gate.derive(ROOT)
ACTIONS = sorted(DERIVED)
ROUTES = sorted(route for found in DERIVED.values() for route in found["routes"])
#: A route is `owner/token`, and one owner can carry several. Deleting by owner
#: and token is enough because the `#n` suffix only ever indexes repeats.
UNIQUE_ROUTES = sorted(set(ROUTES))


def tree(tmp_path):
    """A checkout carrying the real module (comments stripped) and the real ledger."""
    (tmp_path / "formal").mkdir()
    (tmp_path / "assurance").mkdir()
    text = ghost_gate.strip_comments((ROOT / ghost_gate.MODULE).read_text())
    (tmp_path / ghost_gate.MODULE).write_text(text)
    shutil.copy(ROOT / ghost_gate.LEDGER, tmp_path / ghost_gate.LEDGER)
    return tmp_path


def slice_of(text, name):
    """(start, end) of `name`'s definition inside a comment-free module."""
    marks = [(m.group(1), m.start()) for m in ghost_gate.DEF.finditer(text)]
    for index, (found, start) in enumerate(marks):
        if found != name:
            continue
        end = marks[index + 1][1] if index + 1 < len(marks) else len(text)
        return start, end
    raise AssertionError(f"{name} is no longer a definition of the module")


def drop(root, route):
    """Delete one route from the module in `root`, and nothing else.

    A literal becomes a different invariant's name so the assignment stays
    well-formed; an alias becomes the empty set. Either way the module still
    parses, which is the point — a deletion that breaks the spec would be caught
    by `tla-lint.py` instead and would prove nothing about this row.
    """
    owner, _, token = route.partition("/")
    token = token.split("#")[0]
    path = root / ghost_gate.MODULE
    text = path.read_text()
    start, end = slice_of(text, owner)
    body = text[start:end]
    needle = f'"{ghost_gate.INVARIANT}"' if token == "literal" else token
    replacement = '"NoTokenAfterInvalidation"' if token == "literal" else "{}"
    assert needle in body, (route, needle)
    path.write_text(text[:start] + body.replace(needle, replacement, 1) + text[end:])


def findings(root):
    return ghost_gate.audit(root)[0]


def about(problems, name):
    return [p for p in problems if p.startswith(f"{name}:")]


def test_the_real_tree_is_green():
    assert findings(ROOT) == []


def test_the_fixture_is_the_real_module(tmp_path):
    """The comment strip is not a mutation: same actions, same routes."""
    root = tree(tmp_path)
    assert ghost_gate.derive(root) == DERIVED
    assert findings(root) == []


@pytest.mark.parametrize("action", ACTIONS)
def test_deleting_every_route_of_an_action_is_found(tmp_path, action):
    root = tree(tmp_path)
    for route in DERIVED[action]["routes"]:
        drop(root, route)
    problems = about(findings(root), action)
    assert problems, (action, findings(root)[:3])
    assert any("records NoAuthorizationBypass nowhere" in p for p in problems), problems


#: The three actions that record by TWO independent routes. Deleting one leaves
#: the name in the set, so ONLY a route count reports it — which is the arm a
#: per-action name equality was measured to pass over a half-deleted guard.
TWO_ROUTE = sorted(a for a in ACTIONS if len(DERIVED[a]["routes"]) > 1)


@pytest.mark.parametrize("route", UNIQUE_ROUTES)
def test_deleting_one_route_of_an_action_is_found(tmp_path, route):
    root = tree(tmp_path)
    drop(root, route)
    problems = findings(root)
    owner = route.partition("/")[0]
    if owner in TWO_ROUTE:
        assert any(route in p and "gone:" in p for p in problems), (route, problems[:3])
    else:
        # Its only route: the action leaves the derived set entirely, so the
        # finding is the stale-entry one. Reported either way, and the direction
        # is what the assertion above is for.
        assert any("records NoAuthorizationBypass nowhere" in p for p in problems), (
            route,
            problems[:3],
        )


@pytest.mark.parametrize("action", TWO_ROUTE)
def test_a_half_deleted_guard_is_not_a_pass(tmp_path, action):
    """A name-set equality is GREEN here and this row is not: after one of the
    two deletions the action still records, so its name is still in the set."""
    root = tree(tmp_path)
    gone = DERIVED[action]["routes"][0]
    drop(root, gone)
    assert ghost_gate.derive(root)[action]["routes"], action
    assert any(gone in p and "gone:" in p for p in about(findings(root), action))


def test_an_action_that_starts_recording_arrives_unowned(tmp_path):
    root = tree(tmp_path)
    path = root / ghost_gate.MODULE
    text = path.read_text()
    start, end = slice_of(text, "StopUsingToken")
    body = text[start:end].replace(
        "UNCHANGED <<", f'viol\' = viol \\cup {{"{ghost_gate.INVARIANT}"}}\n    /\\ UNCHANGED <<', 1
    )
    path.write_text(text[:start] + body + text[end:])
    problems = about(findings(root), "StopUsingToken")
    assert any("has no entry" in p for p in problems), findings(root)[:3]


def test_a_guard_swapped_under_a_surviving_route_is_found(tmp_path):
    """The second axis: the route stays, the policy it consults does not."""
    root = tree(tmp_path)
    path = root / ghost_gate.MODULE
    text = path.read_text()
    start, end = slice_of(text, "RegisterTouched")
    body = text[start:end].replace("TouchPolicy", "ButtonFreePolicy", 1)
    path.write_text(text[:start] + body + text[end:])
    problems = about(findings(root), "RegisterTouched")
    assert any("policie(s)" in p and "TouchPolicy" in p for p in problems), problems


def test_a_helper_route_reaches_every_caller(tmp_path):
    """`PinAttempt` records once and four actions inherit it, so deleting the
    helper's one route must name all four rather than the helper."""
    root = tree(tmp_path)
    drop(root, "PinAttempt/literal")
    problems = findings(root)
    for caller in ("GetPinToken", "WrongPin", "MintPpuat", "ChangePinStart"):
        assert about(problems, caller), (caller, problems[:3])
    assert not about(problems, "PinAttempt"), problems


def test_a_second_alias_arrives_as_routes_and_not_as_silence(tmp_path):
    root = tree(tmp_path)
    path = root / ghost_gate.MODULE
    text = path.read_text()
    start, end = slice_of(text, "TokenBypass")
    text = (
        text[:start]
        + f'SecondBypass ==\n    {{"{ghost_gate.INVARIANT}"}}\n\n'
        + text[start:]
    )
    start, end = slice_of(text, "CmNext")
    body = text[start:end].replace("viol \\cup {", "viol \\cup SecondBypass \\cup {", 1)
    path.write_text(text[:start] + body + text[end:])
    assert any("new: CmNext/SecondBypass" in p for p in findings(root)), findings(root)


def test_a_stale_entry_is_found(tmp_path):
    root = tree(tmp_path)
    ledger = root / ghost_gate.LEDGER
    ledger.write_text(
        ledger.read_text() + '\n[[action]]\nname = "Tick"\nroutes = []\npolicies = []\n'
        'why = "it does not"\n'
    )
    assert any("stale entry" in p for p in about(findings(root), "Tick")), findings(root)


def test_an_owner_with_no_reason_is_not_one(tmp_path):
    root = tree(tmp_path)
    ledger = root / ghost_gate.LEDGER
    text = ledger.read_text()
    head, _, tail = text.partition('name = "AssertFinish"')
    body, _, rest = tail.partition("\n\n")
    ledger.write_text(
        head
        + 'name = "AssertFinish"'
        + "\n".join(
            line for line in body.splitlines() if not line.startswith("why = ")
        )
        + '\nwhy = ""\n\n'
        + rest
    )
    assert any("'why' is empty" in p for p in findings(root)), findings(root)


def test_an_empty_derivation_trips_its_own_floor(tmp_path):
    """Every rule above passes over a roster of nothing, which is the failure a
    verdict column cannot show."""
    root = tree(tmp_path)
    (root / ghost_gate.MODULE).write_text("Next == FALSE\n")
    problems = findings(root)
    assert any("under the floor of" in p for p in problems), problems


def test_main_prints_a_summary_and_reports_findings(tmp_path, capsys, monkeypatch):
    assert ghost_gate.main() == 0
    assert capsys.readouterr().out.startswith("ghost-gate: ok —")
    root = tree(tmp_path)
    drop(root, "CmNext/literal")
    monkeypatch.setattr(ghost_gate, "ROOT", root)
    assert ghost_gate.main() == 1
    assert "CmNext" in capsys.readouterr().err
