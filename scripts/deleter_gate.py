#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the delete-family caller dispositions against the tree, both ways.

`Fs::delete`, `Fs::delete_key` and `Fs::force_delete` all remove the value
whatever their metadata drop did, and all three RETURN what the drop did — `Err`
names a state (the value is gone, a record may still stand over it) rather than a
no-op. Which callers may discard that answer and which may not is a judgement per
call site, and `assurance/deleters.toml` is where those judgements live.

A ledger of judgements is only worth the roster under it. This one is DERIVED
here and compared with the file; nothing about which sites exist is stored. Two
findings in this tree are why:

* `assurance/crates.toml` exists because two roadmap drafts enumerated crates
  from memory and missed four, including the second-largest;
* the audit this file comes out of began by refuting a sentence in
  `docs/store-refinement.md` that named "the one caller in the tree that deletes
  a fid carrying a head". There were two, and the second was the one hiding a
  faulted drop, on the reset path.

What is checked, and the direction of each:

* every derived call site has exactly one entry, and every entry names a site
  that is still there. A new caller arrives unaudited and the row goes red;
* the `answer` recorded — whether the site reads the deleter's `Result` or
  discards it into `let _ =` — is DERIVED from the statement, so turning a
  reading caller into a discarding one cannot pass as an unrelated edit;
* `disposition` and `answer` must agree: `must-read` needs `read`,
  `best-effort` needs `discarded`. That is the pair that makes the judgement
  falsifiable by the code rather than by a reviewer's memory;
* the call text at the recorded line must still be that call. A citation whose
  line has moved reports where it went, the way `citation_gate.py` does;
* `metadata = "drops-head"` is allowed only for a crate that actually mints
  EF_META heads, and that set is derived too. The whole metadata axis rests on
  "`rsk-piv` mints the only heads"; a second minter arriving silently is how that
  premise stops being true while every disposition still reads as though it is;
* the roster is not empty. A derivation that finds nothing satisfies every rule
  above, which is the failure mode a verdict column cannot show.

Deliberately not here: whether a disposition is *right*. That is prose in the
ledger, and no script can check it. What this row keeps honest is that each one
is still about a site that exists, still describes what that site does with the
answer, and still covers every site there is.
"""

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = pathlib.Path("assurance/deleters.toml")

#: The three removal verbs. `delete_key` is `delete` over a `KeyFid`, so it
#: carries the identical contract; `force_delete` differs only in that the
#: backend removal is unconditional (see its rustdoc).
VERBS = ("delete", "delete_key", "force_delete")
#: The leading `.` is the whole receiver test: it is what separates `fs.delete(`
#: from `Foo::delete(` and from any `_delete(` suffix of a longer name. Longest
#: alternative last is deliberate — `delete` is tried first and the `\s*\(` after
#: it is what sends `.delete_key(` back for the longer one.
CALL = re.compile(rf"\.({'|'.join(VERBS)})\s*\(")

#: Where a delete caller cannot be. `crates/rsk-fs` defines the family, so its
#: own uses are the implementation rather than callers of it; `fuzz/` drives the
#: API rather than shipping a decision. Held to the roadmap's own wording, so the
#: counts here reproduce the ones §3.4 records. Nothing else is excluded by name:
#: `third_party/` stays in, because a call there would be a decision too.
SKIP_DIRS = ("crates/rsk-fs", "fuzz")

#: Not scope — determinism. `tools/emu` and `tools/tui` are their own workspaces
#: with their own `target/`, and a build there drops generated `.rs` under the
#: checkout, so a roster walking the tree would depend on whether anyone had run
#: cargo. Matched by path COMPONENT, at any depth.
BUILD_DIRS = frozenset({"target", "book", ".git", ".direnv", "node_modules"})

#: A cfg-gated source by the convention AGENTS.md states: tests and proofs live
#: in sibling files hooked with `#[path]`. Derived from the naming rule rather
#: than listed, so `reset_refinement_kani.rs` — whose `reset.delete` is the
#: refinement model's own verb, not this file system's — is out by the rule that
#: puts every other proof file out.
CFG_GATED = re.compile(r"(?:^|_)(tests|kani)\.rs$")

#: Where an EF_META head can come from. Derived, because every `drops-head`
#: disposition below rests on the answer being one crate.
MINT = re.compile(r"\.meta_add(?:_reserve)?\s*\(")

#: A statement that throws the answer away. `let _ = …`, in the spellings rustfmt
#: leaves behind.
DISCARD = re.compile(r"^\s*let\s+_\s*(?::[^=]*)?=")

#: A statement boundary: the line before a statement's first line ends in one of
#: these, or is blank, or is a comment. Walking back to it is what lets a call on
#: a `.method()` continuation line be read against the `let` that owns it.
BOUNDARY = re.compile(r"[;{},]$|^$|^//|^/\*|^\*")

#: The roster cannot shrink to nothing without someone saying so. Measured at 43
#: (33 `delete`/`delete_key` + 10 `force_delete`) when this landed; floored well
#: under that so ordinary movement does not trip it and a broken derivation does.
FLOOR_SITES = 30

DISPOSITIONS = {"must-read": "read", "best-effort": "discarded"}
#: The derived `answer` as a verb, so a message reads as a sentence.
PHRASE = {"read": "reads", "discarded": "discards"}
CLASSES = ("wipe-sweep", "secret-or-gate", "metadata", "bookkeeping")
METADATA = ("drops-head", "none")


def sources(root):
    """Every `.rs` file a delete caller could live in, in a stable order."""
    out = []
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        parts = rel.split("/")
        if BUILD_DIRS.intersection(parts) or parts[0].startswith("result"):
            continue
        if any(rel == d or rel.startswith(d + "/") for d in SKIP_DIRS):
            continue
        if CFG_GATED.search(path.name):
            continue
        out.append((rel, path))
    return out


def statement_head(lines, index):
    """The first line of the statement `lines[index]` belongs to.

    A call can sit on a `.method()` continuation, where the `let _ =` that
    discards it is lines above. Reading only the call's own line calls every one
    of those a reader, which is the direction that hides a discard.
    """
    at = index
    while at > 0 and not BOUNDARY.search(lines[at - 1].strip()):
        at -= 1
    return lines[at]


def sites(root):
    """[(file, line, call text, verb, answer)] for the whole checkout."""
    found = []
    for rel, path in sources(root):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            for hit in CALL.finditer(line):
                answer = (
                    "discarded"
                    if DISCARD.match(statement_head(lines, number - 1))
                    else "read"
                )
                found.append((rel, number, line.strip(), hit.group(1), answer))
    return found


def minters(root):
    """The crates that write an EF_META head, derived from the calls."""
    out = set()
    for rel, path in sources(root):
        if MINT.search(path.read_text()):
            out.add("/".join(rel.split("/")[:2]))
    return out


def entries(root):
    with (root / LEDGER).open("rb") as handle:
        return tomllib.load(handle)


def audit(root):
    """Every disagreement between the ledger and the tree, each reported once."""
    problems = []
    doc = entries(root)
    derived = sites(root)
    if len(derived) < FLOOR_SITES:
        problems.append(
            f"{len(derived)} call sites derived, under the floor of {FLOOR_SITES}"
            " — the derivation found (almost) nothing, so every rule below passed"
            " over an empty roster"
        )
        return problems

    ledger = {(e["file"], e["line"]): e for e in doc.get("site", [])}
    if len(ledger) != len(doc.get("site", [])):
        problems.append("two entries name the same file and line")

    by_key = {(rel, line): (call, verb, answer) for rel, line, call, verb, answer in derived}
    for key in sorted(by_key.keys() - ledger.keys()):
        rel, line = key
        problems.append(
            f"{rel}:{line} `{by_key[key][0]}` calls the delete family and"
            f" {LEDGER} does not dispose of it"
        )
    for key in sorted(ledger.keys() - by_key.keys()):
        rel, line = key
        elsewhere = [
            str(n) for r, n, call, _, _ in derived
            if r == rel and call == ledger[key]["call"]
        ]
        where = f"; it is at :{', :'.join(elsewhere)} now" if elsewhere else ""
        problems.append(
            f"{LEDGER} disposes of {rel}:{line}, which calls nothing{where}"
        )

    for key in sorted(by_key.keys() & ledger.keys()):
        rel, line = key
        call, verb, answer = by_key[key]
        entry = ledger[key]
        if entry["call"] != call:
            problems.append(
                f"{rel}:{line} was disposed of as `{entry['call']}` and reads"
                f" `{call}` now"
            )
        if entry["verb"] != verb:
            problems.append(f"{rel}:{line} calls `{verb}`, disposed of as `{entry['verb']}`")
        if entry["answer"] != answer:
            problems.append(
                f"{rel}:{line} {PHRASE[answer]} the deleter's answer and is"
                f" disposed of as `{entry['answer']}` — re-decide the site, do not"
                " re-label it"
            )

    mints = minters(root)
    if mints != set(doc["head_minters"]):
        problems.append(
            f"the crates that write an EF_META head are {sorted(mints)}, and"
            f" {LEDGER} says {sorted(doc['head_minters'])} — every `drops-head`"
            " disposition rests on that set"
        )
    for entry in doc.get("site", []):
        where = f"{entry['file']}:{entry['line']}"
        if entry["class"] not in CLASSES:
            problems.append(f"{where}: class `{entry['class']}` is not one of {CLASSES}")
        if entry["metadata"] not in METADATA:
            problems.append(f"{where}: metadata `{entry['metadata']}` is not one of {METADATA}")
        if entry["disposition"] not in DISPOSITIONS:
            problems.append(
                f"{where}: disposition `{entry['disposition']}` is not one of"
                f" {sorted(DISPOSITIONS)}"
            )
        elif DISPOSITIONS[entry["disposition"]] != entry["answer"]:
            problems.append(
                f"{where}: disposed of as `{entry['disposition']}` while the site"
                f" {PHRASE[entry['answer']]} the answer"
            )
        if not entry.get("why", "").strip():
            problems.append(f"{where}: a disposition with no reason is not one")
        if entry["metadata"] == "drops-head" and "/".join(
            entry["file"].split("/")[:2]
        ) not in mints:
            problems.append(
                f"{where}: claims to drop an EF_META head from a crate that mints none"
            )
    return problems


def run(root):
    try:
        problems = audit(root)
    except (KeyError, OSError, tomllib.TOMLDecodeError) as error:
        problems = [f"{LEDGER} cannot be read as a disposition ledger: {error}"]
    if problems:
        print("deleter-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEvery caller of Fs::delete / delete_key / force_delete owes a\n"
            "disposition: whether discarding the deleter's answer is an allowed\n"
            "best-effort wipe there, or a device reporting success over a record\n"
            "or a secret that is still in flash. Decide the site in\n"
            f"{LEDGER}; a label that disagrees with the code is not a decision.",
            file=sys.stderr,
        )
        return 1
    total = len(sites(root))
    print(f"deleter-gate: ok — {total} call sites, each disposed of")
    return 0


def main():
    if sys.argv[1:]:
        print("usage: deleter_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
