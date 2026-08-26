#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the property × build-configuration matrix against the tree it is about.

Every assurance claim this project makes reads as being about "the firmware",
and the firmware is not one thing. `nix build` produces nineteen named images,
`firmware/Cargo.toml` carries features no flake package expresses, and
`firmware/boards/` is a third axis under both. A property proved on the default
build is, without a per-configuration disposition, silently asserted about
builds where the thing it is about does not exist — the sharpest case being the
four `no-touch` packages, which remove the physical-consent gate that the
P0-launch authorization properties are about.

So: columns are DERIVED from `nix/firmware.nix`, `firmware/Cargo.toml` and
`firmware/boards/`, rows from `assurance/properties.toml`, and neither is
written down anywhere a hand can edit. `assurance/configurations.toml` holds the
half no derivation can produce — what each cell's disposition IS — and
`docs/assurance-matrix.md` is regenerated from both and diffed, the way
`config_gen_gate.py` diffs `formal/*.cfg`. A new package, a new feature, a new
board or a new P0-family property therefore arrives as forty (or thirty-one)
`gap` cells in a file that no longer matches its generator, which is the row
going red.

The five dispositions are the roadmap's: `covered`, `equivalent`, `conditional`,
`out-of-scope`, `gap`. A cell with anything else is refused, and so is an
`equivalent` cell whose basis is missing — that pair is the whole point of the
row, because "the names look similar" is exactly how a false equivalence gets
written. `equivalent` accepts ONE basis, [`SAME_FEATURES`], and it is machine
checked: the two columns' derived per-crate cargo-feature closures must be
equal. `firmware-display` cannot be equivalent to `firmware` under that rule,
and neither can any `no-touch` package, whatever a reviewer believes.

No disposition rests on prose. Each one asserts something about the tree —
`covered` that the evidence was produced HERE, `out-of-scope` that the code or
the gate is absent — so each names a basis the tree can disagree with, and
[`ALLOWED`] says which. The one unchecked basis this file shipped with was the
hole the rest of it was built to close: `equivalent` was refused on it because
it asserts sameness, and `covered` asserts MORE and took it, so every un-placed
cell could be re-declared `covered` and the row still printed ok.

What this cannot say, deliberately: whether a disposition is RIGHT. `why` is
prose and no script reads it for truth. What the row keeps honest is that every
applicable cell has one, that an `equivalent` names a column it really does
compile like, that an `out-of-scope` claiming an absent crate is claiming one
that is really absent, and that a column carrying `gap` cells also carries the
question that would settle them — a `gap` with no question is a shrug with a
verdict column.
"""

import functools
import pathlib
import re
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parents[1]

LEDGER = pathlib.Path("assurance/configurations.toml")
REGISTRY = pathlib.Path("assurance/properties.toml")
ARTIFACT = pathlib.Path("docs/assurance-matrix.md")
FLAKE = pathlib.Path("nix/firmware.nix")
MANIFEST = pathlib.Path("firmware/Cargo.toml")
BOARDS = pathlib.Path("firmware/boards")
RELEASE = pathlib.Path(".github/workflows/release-build.yml")
CHECK = pathlib.Path("scripts/check.sh")

#: The roadmap's five values. A sixth is not a new kind of evidence, it is a
#: cell nobody classified.
DISPOSITIONS = ("covered", "equivalent", "conditional", "out-of-scope", "gap")
#: What a `[[cell]]` may DECLARE. `gap` is missing on purpose: by this file's
#: design a gap is the ABSENCE of a cell, and a declared one puts the cell in the
#: placed set — which took the column out of the "owes a settling question" rule
#: while the grid still printed `gap` in all 37 of its cells.
DECLARABLE = tuple(d for d in DISPOSITIONS if d != "gap")
#: Three letters each, so a 31-column grid fits a page.
CODE = {
    "covered": "cov",
    "equivalent": "equ",
    "conditional": "cnd",
    "out-of-scope": "oos",
    "gap": "gap",
}

#: The one basis `equivalent` accepts, and the reason it is the only one: it is
#: the only claim of sameness this tree can CHECK. The cell names `same_as`, and
#: the two columns' derived per-crate feature closures must be identical — so
#: the delta between them is knobs — and the cell has to WRITE THOSE DOWN in
#: `knob_delta`, which is checked too. Without that half the rule was vacuous on
#: every cell that used it: all of them compared an empty feature set with an
#: empty one, while `FLASH_SIZE`, `KVMAIN`, `LED_KIND` and `led_order` — real
#: `rustc-env`/`rustc-cfg` inputs, and a regenerated `memory.x` — moved unread.
SAME_FEATURES = "same-cargo-features"
#: The property's owner crates are not compiled into this column at all. Checked
#: against the same feature resolution, so `rsk-ui` being absent is a fact and
#: not a recollection.
CRATE_ABSENT = "crate-absent"
#: The cell names `feature`; the column enables it, and production Rust really
#: does gate on it. What the gate is (a `no-touch` presence auto-confirm, say)
#: is the `why`'s job; that the switch exists and is thrown here is this one's.
GATE_COMPILED_OUT = "gate-compiled-out"
#: This column IS the default build: no cargo features, no knobs.
DEFAULT_BUILD = "default-build"
#: The cell names `evidence`: `check.sh` rows that build THIS configuration —
#: same cargo features, same build knobs. `covered` is the strongest word in the
#: vocabulary and it was the only one resting on nothing, so every un-placed cell
#: could be re-declared `covered` and the row still printed ok.
CHECK_SH_ROWS = "check-sh-rows"
BASES = (SAME_FEATURES, CRATE_ABSENT, GATE_COMPILED_OUT, DEFAULT_BUILD, CHECK_SH_ROWS)
#: Which bases each disposition may rest on. There is deliberately no unchecked
#: one left: `stated` used to be legal for everything except `equivalent`, and
#: writing a STRONGER word than the rule refused — `covered`, or `conditional`,
#: or `out-of-scope` — retired all 955 `gap` cells at EXIT=0. Every disposition
#: asserts something about the tree, so the tree has to be able to disagree.
ALLOWED = {
    "covered": (DEFAULT_BUILD, CHECK_SH_ROWS),
    "conditional": (DEFAULT_BUILD, CHECK_SH_ROWS),
    "equivalent": (SAME_FEATURES,),
    "out-of-scope": (CRATE_ABSENT, GATE_COMPILED_OUT),
}

#: The tranches §5 of the roadmap defines. `p0-launch` + `p0b` is the P0 family,
#: and the P0 family is the matrix's rows; the other two are carried so the
#: classification is TOTAL over the registry. A property nobody classified would
#: otherwise be a row nobody misses.
TRANCHES = ("p0-launch", "p0b", "p1", "out-of-queue")
ROW_TRANCHES = ("p0-launch", "p0b")

#: Floors, AT today's counts rather than under them. A derivation that finds
#: (almost) nothing satisfies every rule below over an empty roster, which is the
#: shape seven guards in this tree have shipped with — but 12 against 19 packages
#: catches only the collapse, never the slide, and losing four boards one at a
#: time is how an axis quietly stops being an axis. Shrinking one for real is
#: then a deliberate edit here, in the same diff as the shrink.
FLOOR_PACKAGES = 19
FLOOR_BOARDS = 6
FLOOR_ROWS = 40
#: A `why` or a settling question shorter than this is a placeholder rather than
#: prose: `.strip()` alone let `"?"` and `"TODO"` stand as the question that would
#: settle a whole column. Six, because the ledger's shortest real question is
#: seven words and its shortest `why` is forty-five. It catches a placeholder;
#: no script can catch a bad question.
FLOOR_WORDS = 6

#: A property tag in production Rust. Same two spellings `assurance_gate.py`
#: validates; read here only for WHICH CRATE owns each property, which is what
#: `crate-absent` rests on.
OWNER_TAG = re.compile(
    r"(?:Refines|Supports)\s+`[A-Za-z0-9]+![A-Za-z0-9]+`\s+—\s+(SEC-[A-Z]+-[0-9A-Z]+)"
)

#: `--features a,b` / `--features=a,b`, in the spellings cargo takes. Used on
#: `check.sh` rows AND on a flake package's `cargoFlags`, because a hand-rolled
#: word scan over the latter read `--features=a,b` as no features at all — and an
#: empty feature set is what makes a column look like the default build.
FEATURE_FLAG = re.compile(r"(?<![\w-])--features[=\s]+([\w,.-]+)")
#: `cargoFlags = [ … ]` in the spellings NIX takes, not the one nixfmt happens to
#: write: no `nixfmt --check` row exists in this tree, so `cargoFlags= [`,
#: `cargoFlags  = [` and `cargoFlags =[` are as real as the canonical form — and
#: each read as NO flags, which prints a published flavor as the default build.
CARGO_FLAGS = re.compile(r"(?<![\w-])cargoFlags\s*=\s*\[(.*?)\]", re.S)
#: The key on its own, to tell "this package sets no cargoFlags" from "it sets
#: them to something this gate cannot read".
CARGO_FLAGS_KEY = re.compile(r"(?<![\w-])cargoFlags\s*=")
#: A literal string in a Nix list.
NIX_STRING = re.compile(r'"([^"]*)"')
#: `attr = mkFirmware { … }`, in the spellings nixfmt leaves and the ones it does
#: not: the `=` and the call may be on separate lines (this file already breaks
#: two other bindings that way), the indent is not fixed, and `mkFirmware{` is
#: legal Nix. Nothing in `check.sh` runs `nixfmt --check`, so the shape cannot be
#: assumed.
PACKAGE = re.compile(r"^[ \t]*([A-Za-z0-9_-]+)\s*=\s*mkFirmware\s*\{", re.M)
#: Every call of the builder, however it is written. The count is compared with
#: what [`PACKAGE`] matched: a package the pattern above cannot see is a column
#: that never exists, and this is the only thing that notices.
INVOCATION = re.compile(r"(?<![\w-])mkFirmware\s*\{")
#: A `key = value;` inside a package body. Not `^`-anchored: a one-line body is
#: legal and the anchored version dropped its knobs, which turned the package
#: into the default build in the matrix.
KNOB = re.compile(r"(?<![\w-])([a-zA-Z][A-Za-z0-9]*)\s*=\s*([^;]+);")
#: Nothing in a package body is a knob under these names: the image's name, and
#: the raw `cargoFlags` list, whose feature half is the feature axis and whose
#: residual half [`cargo_flags`] re-adds as one knob.
NOT_A_KNOB = ("name", "cargoFlags")
#: A `check.sh` row: `run "<label>" <command>`, or the `run_tests` sibling. The
#: label is how a `covered` cell names its evidence.
ROW = re.compile(r'^run(?:_tests)?\s+"([^"]+)"\s+(\S.*)$')
#: A `VAR=value` in a row's `env` prefix — the build knobs that row pins.
ROW_ENV = re.compile(r"(?<![\w-])([A-Z][A-Z0-9_]*)=(\S+)")
#: The release workflow's flavor loop.
PKG_LOOP = re.compile(r"for pkg in ([^;]+); do")
#: Both of them: the build and the reproducibility rebuild are two lists that
#: have to be one, and without a floor a reflow that hides one of them leaves the
#: comparison running over a single list, in silence.
FLOOR_LOOPS = 2

#: What a broken input raises before it can become a finding. A traceback is a
#: red too, and a much worse one: it names a line of this file rather than the
#: file whose shape changed.
MALFORMED = (AttributeError, KeyError, OSError, TypeError, tomllib.TOMLDecodeError)

GENERATED_BY = "Generated by scripts/matrix_gate.py --write"


# --- the tree ---------------------------------------------------------------


def _nix_blocks(text):
    """(attr, body) for each `attr = mkFirmware { … };` in the packages set."""
    for found in PACKAGE.finditer(text):
        at, depth = found.end() - 1, 0
        for index in range(at, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    yield found.group(1), text[at + 1 : index]
                    break


def cargo_flags(name, body):
    """(cargo features, the rest of the list) for one package's `cargoFlags`.

    The rest is a knob and not a footnote: `--no-default-features` and
    `--profile release-fast` build a different image, and a column whose derived
    features AND knobs are both empty IS the default build — which is a basis the
    gate accepts and an equivalence whose whole delta reads as nothing.
    """
    found = CARGO_FLAGS.search(body)
    if not found:
        if CARGO_FLAGS_KEY.search(body):
            raise ValueError(
                f"{FLAKE}: `{name}` sets cargoFlags to something this gate cannot read as"
                " a list of literal flags — a flag it cannot read is a column derived wrong"
            )
        return (), ""
    unread = NIX_STRING.sub(" ", found.group(1)).strip()
    if unread:
        raise ValueError(
            f"{FLAKE}: `{name}`'s cargoFlags carries {unread!r}, which is not a literal"
            " flag — a flag this gate cannot read is a column derived wrong"
        )
    joined = " ".join(NIX_STRING.findall(found.group(1)))
    features = tuple(f for group in FEATURE_FLAG.findall(joined) for f in group.split(","))
    return features, " ".join(FEATURE_FLAG.sub(" ", joined).split())


def packages(root):
    """The flake's firmware images: name -> (features, knobs).

    Keyed by the `name` each package builds, not by the attribute: `default` and
    `firmware` are one image under two attributes, and counting them twice would
    put a phantom column in the matrix.
    """
    text = (root / FLAKE).read_text()
    code = "\n".join(
        gate_lines.split_at_comment(body)[0] for _indent, body in gate_lines.logical_lines(text)
    )
    out = {}
    for _attr, body in _nix_blocks(text):
        name = re.search(r'name\s*=\s*"([^"]+)"', body).group(1)
        features, residual = cargo_flags(name, body)
        knobs = {
            key: value.strip().strip('"')
            for key, value in KNOB.findall(body)
            if key not in NOT_A_KNOB
        }
        if residual:
            knobs["cargoFlags"] = residual
        derived = (frozenset(features), knobs)
        if out.setdefault(name, derived) != derived:
            raise ValueError(
                f"{FLAKE} builds `{name}` from two mkFirmware blocks that derive"
                f" differently — {sorted(out[name][0])} {out[name][1]} and"
                f" {sorted(features)} {knobs}. One image name is one column, so the"
                " second block replaced the first with no message at all"
            )
    seen, called = len(list(_nix_blocks(text))), len(INVOCATION.findall(code))
    if seen != called:
        raise ValueError(
            f"{FLAKE} calls mkFirmware {called} time(s) and this gate reads {seen}"
            " package(s) — a package written in a spelling the pattern cannot see is"
            " a column that never exists"
        )
    return out


def published(root):
    """The packages `release-build.yml` ships, and whether its two lists agree."""
    text = (root / RELEASE).read_text()
    loops = [
        frozenset(PKG_LOOP.search(body).group(1).split())
        for body, executed in gate_lines.yaml_runs(text)
        if executed and PKG_LOOP.search(gate_lines.split_at_comment(body)[0])
    ]
    return loops


def boards(root):
    """`firmware/boards/**/*.toml`: preset -> the knobs it sets, flattened.

    Recursive, because `build.rs` reads `boards/{BOARD}.toml` with no rule
    against a `/` in the name — so `BOARD=vendor/foo` builds from a nested file a
    flat glob calls no board at all.
    """
    out = {}
    for path in sorted((root / BOARDS).rglob("*.toml")):
        doc = tomllib.loads(path.read_text())
        out[path.relative_to(root / BOARDS).with_suffix("").as_posix()] = {
            f"{section}.{key}": value
            for section, body in doc.items()
            for key, value in body.items()
        }
    return out


def manifest_features(root):
    return tuple(tomllib.loads((root / MANIFEST).read_text())["features"])


def check_sh_rows(root):
    """label -> (cargo features, env knobs, command) for every `check.sh` row.

    One reader for both things the ledger asks of `check.sh`: which features
    reach a build of `firmware`, and whether the row a `covered` cell names
    builds the column it claims about. Read off each row's CODE — a commented-out
    row is not a row, and it is not evidence either.
    """
    out = {}
    for _indent, body in gate_lines.logical_lines((root / CHECK).read_text()):
        found = ROW.match(gate_lines.split_at_comment(body)[0].strip())
        if not found:
            continue
        label, command = found.groups()
        features = frozenset(
            feature for group in FEATURE_FLAG.findall(command) for feature in group.split(",")
        )
        # The knobs sit in the `env …` prefix, ahead of the cargo they wrap.
        env = {
            key: value.strip('"')
            for key, value in ROW_ENV.findall(command.split(" cargo ", 1)[0])
        }
        if label in out:
            raise ValueError(
                f"{CHECK} has two rows named {label!r} — a cell's evidence would name"
                " both and the gate would read one of them"
            )
        out[label] = (features, env, command)
    return out


def check_sh_firmware_features(root):
    """Every feature a `check.sh` row hands to a build of `firmware`.

    The rule this serves is the roadmap's: a cargo feature with a `check.sh` row
    and no column.
    """
    return {
        feature
        for features, _env, command in check_sh_rows(root).values()
        if "cargo " in command and "firmware" in gate_lines.packages(command)
        for feature in features
    }


def env_name(knob):
    """The env var `mkFirmware` hands `build.rs` for the flake argument `knob`.

    Mechanical (`flashSize` -> `FLASH_SIZE`), because the flake writes the pair
    itself and a table here would go stale beside `build.rs`. A board preset's
    keys (`flash.size_mb`) are a third vocabulary and deliberately map to
    nothing: a row reaches a board by its NAME, not by spelling its keys out.
    """
    return re.sub(r"(?<!^)(?=[A-Z])", "_", knob).upper()


# --- cargo feature resolution ----------------------------------------------


def _deps(doc):
    out = {}
    for section in ("dependencies", "build-dependencies"):
        for name, spec in doc.get(section, {}).items():
            out[name] = spec if isinstance(spec, dict) else {}
    return out


def workspace(root):
    """package name -> its parsed manifest, for every [workspace] member."""
    members = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["members"]
    out = {}
    for member in members:
        doc = tomllib.loads((root / member / "Cargo.toml").read_text())
        out[doc["package"]["name"]] = doc
    return out


def resolve(manifests, extra):
    """(crates compiled in, crate -> its enabled features) for `firmware` + `extra`.

    Cargo's own resolution, over workspace members only: an external crate cannot
    own a property, so its features would be a column nothing reads. Weak
    (`dep?/feat`) edges fire only when the optional dependency is already in,
    which is what makes `fips-profile` leave `rsk-display` alone on a build
    without a screen.
    """
    enabled, present, queue, held = {}, set(), [], []

    def add(crate):
        if crate not in manifests or crate in present:
            return
        present.add(crate)
        for name, spec in _deps(manifests[crate]).items():
            if not spec.get("optional"):
                add(name)
        queue.append((crate, "default"))

    add("firmware")
    queue.extend(("firmware", feature) for feature in extra)

    seen = set()
    while True:
        while queue:
            crate, feature = queue.pop()
            if crate not in manifests or (crate, feature) in seen:
                continue
            seen.add((crate, feature))
            table = manifests[crate].get("features", {})
            deps = _deps(manifests[crate])
            if feature not in table:
                # An optional dependency doubles as an implicit feature of its name.
                if deps.get(feature, {}).get("optional"):
                    add(feature)
                    enabled.setdefault(crate, set()).add(feature)
                continue
            enabled.setdefault(crate, set()).add(feature)
            for item in table[feature]:
                if item.startswith("dep:"):
                    add(item[4:])
                elif "/" in item:
                    dep, sub = item.split("/", 1)
                    is_weak = dep.endswith("?")
                    dep = dep.rstrip("?")
                    if is_weak:
                        held.append((dep, sub))
                        continue
                    add(dep)
                    queue.append((dep, sub))
                else:
                    queue.append((crate, item))
        # A `dep?/feat` edge fires only once its optional dependency is in, and
        # the edge is usually walked before it arrives. Re-offering the held ones
        # until nothing moves is what makes the answer independent of the order
        # the features were given in.
        live = [pair for pair in held if pair[0] in present]
        if not live:
            break
        held = [pair for pair in held if pair not in live]
        queue.extend(live)
    return frozenset(present), {c: frozenset(f) for c, f in enabled.items()}


# --- the axes ---------------------------------------------------------------


class Column:
    """One buildable configuration: what it turns on, and what that compiles."""

    def __init__(self, name, kind, features, knobs, is_published, manifests):
        self.name = name
        self.kind = kind
        self.features = frozenset(features)
        self.knobs = knobs
        self.published = is_published
        self.present, self.closure = resolve(manifests, sorted(self.features))

    @property
    def default(self):
        return not self.features and not self.knobs


def columns(root, manifests):
    """Every column, derived from the three axes, in a stable order."""
    out, loops = [], published(root)
    shipped = frozenset.union(*loops) if loops else frozenset()
    for name, (features, knobs) in packages(root).items():
        out.append(Column(name, "package", features, knobs, name in shipped, manifests))
    expressed = {f for _c in out for f in _c.features}
    for feature in manifest_features(root):
        if feature not in expressed:
            out.append(Column(feature, "feature", [feature], {}, False, manifests))
    for preset, knobs in boards(root).items():
        out.append(Column(preset, "board", [], knobs, False, manifests))
    return out


def owners(root):
    """property id -> the crates whose production Rust carries its tag."""
    found = {}
    files = [*(root / "crates").glob("*/src/**/*.rs"), *(root / "firmware/src").glob("**/*.rs")]
    for path in sorted(files):
        if "kani" in path.name or "tests" in path.name:
            continue
        rel = path.relative_to(root).parts
        crate = rel[1] if rel[0] == "crates" else "firmware"
        for pid in OWNER_TAG.findall(path.read_text(errors="ignore")):
            found.setdefault(pid, set()).add(crate)
    return {pid: frozenset(crates) for pid, crates in found.items()}


def registry(root):
    doc = tomllib.loads((root / REGISTRY).read_text())
    return [(entry["id"], entry["name"]) for entry in doc["property"]]


# --- the ledger -------------------------------------------------------------


def ledger(root):
    return tomllib.loads((root / LEDGER).read_text())


def expand(doc, problems):
    """[((property, column), entry)] for every cell the ledger disposes of."""
    cells = []
    for index, entry in enumerate(doc.get("cell", [])):
        try:
            pids, cols = entry["properties"], entry["columns"]
        except KeyError as missing:
            problems.append(f"cell #{index + 1} has no {missing}")
            continue
        for pid in pids:
            for column in cols:
                cells.append(((pid, column), entry))
    return cells


def audit(root):
    """(problems, one-line summary) for the matrix, the ledger and the artifact."""
    root = pathlib.Path(root)
    problems = []
    manifests = workspace(root)
    cols = columns(root, manifests)
    by_name = {column.name: column for column in cols}
    if len(by_name) != len(cols):
        problems.append("two columns derive to the same name")
    kinds = {kind: [c for c in cols if c.kind == kind] for kind in ("package", "feature", "board")}
    if len(kinds["package"]) < FLOOR_PACKAGES or len(kinds["board"]) < FLOOR_BOARDS:
        problems.append(
            f"derived {len(kinds['package'])} package(s) and {len(kinds['board'])} board(s),"
            f" under the floors of {FLOOR_PACKAGES}/{FLOOR_BOARDS} — an axis that shrank"
            " stopped covering what it used to, and one that collapsed satisfies every"
            " rule below over an empty matrix. Shrink the floor here in the same diff"
        )
        return problems, "matrix-gate: derivation failed"

    loops = published(root)
    if len(loops) < FLOOR_LOOPS:
        problems.append(
            f"{RELEASE} shows {len(loops)} `for pkg in …` flavor loop(s), under the"
            f" floor of {FLOOR_LOOPS} — the build and its reproducibility rebuild are"
            " two lists whose agreement is the check, and one of them is unreadable"
        )
    elif len({frozenset(loop) for loop in loops}) != 1:
        problems.append(
            f"{RELEASE}'s flavor loops disagree: {[sorted(loop) for loop in loops]}"
        )
    for name in sorted(frozenset.union(*loops) if loops else frozenset()):
        if name not in by_name:
            problems.append(f"{RELEASE} publishes {name}, which {FLAKE} does not build")

    # The roadmap's rule is "a cargo feature with a check.sh row and no column".
    # A manifest feature always HAS one — `columns` synthesises it — so the only
    # way to reach the rule is a row naming a feature the manifest no longer
    # defines, and that is the branch. A second `elif` asking whether some column
    # carries it was unreachable by construction, which is a rule that cannot fail.
    manifest = manifest_features(root)
    for feature in sorted(check_sh_firmware_features(root)):
        if feature not in manifest:
            problems.append(
                f"a check.sh row builds firmware with `--features {feature}`, which"
                f" {MANIFEST} does not define — a stale row, or a column nothing can derive"
            )

    try:
        doc = ledger(root)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{LEDGER} cannot be read as a disposition ledger: {error}"], "matrix-gate: no ledger"

    ids = [pid for pid, _name in registry(root)]
    tranche, seen = {}, []
    for name in TRANCHES:
        for pid in doc.get("tranche", {}).get(name, []):
            tranche[pid] = name
            seen.append(pid)
    for pid in sorted(set(seen)):
        if seen.count(pid) > 1:
            problems.append(f"{pid} is in more than one tranche")
    for pid in ids:
        if pid not in tranche:
            problems.append(
                f"{pid} is in {REGISTRY} and in no tranche of {LEDGER} — say which"
                " queue it belongs to, or it is a row the matrix silently has no opinion on"
            )
    for pid in sorted(set(seen) - set(ids)):
        problems.append(f"{LEDGER} puts {pid} in a tranche and {REGISTRY} has no such property")
    for name in sorted(set(doc.get("tranche", {})) - set(TRANCHES)):
        problems.append(f"{LEDGER} names tranche `{name}`, which is not one of {TRANCHES}")

    rows = [pid for pid in ids if tranche.get(pid) in ROW_TRANCHES]
    if len(rows) < FLOOR_ROWS:
        problems.append(
            f"{len(rows)} P0-family row(s), under the floor of {FLOOR_ROWS} — the"
            " tranche lists shrank, and a matrix with fewer rows makes fewer claims"
            " than the one this floor was set at. Shrink the floor here in the same diff"
        )
        return problems, "matrix-gate: derivation failed"

    own = owners(root)
    cells = expand(doc, problems)
    placed = {}
    for key, entry in cells:
        pid, column = key
        where = f"{pid} × {column}"
        if key in placed:
            problems.append(f"{where} is disposed of twice")
            continue
        placed[key] = entry
        if pid not in rows:
            problems.append(
                f"{where}: {pid} is not a P0-family property, so it is not a row of this matrix"
            )
            continue
        if column not in by_name:
            problems.append(f"{where}: no such build configuration")
            continue
        problems.extend(check_cell(root, pid, by_name[column], entry, by_name, own))

    problems.extend(check_chains(placed))

    questions = {q.get("column"): q.get("text", "") for q in doc.get("question", [])}
    for column in sorted(set(questions) - set(by_name)):
        problems.append(f"{LEDGER} carries a settling question for `{column}`, which is no column")
    gaps = {}
    for column in cols:
        open_rows = [pid for pid in rows if (pid, column.name) not in placed]
        if open_rows:
            gaps[column.name] = open_rows
            if len(questions.get(column.name, "").split()) < FLOOR_WORDS:
                problems.append(
                    f"{column.name} has {len(open_rows)} `gap` cell(s) and no settling"
                    f" question in {LEDGER} — a gap with no question is a shrug, and"
                    f" one under {FLOOR_WORDS} words (`?`, `TODO`) is the same shrug"
                )
    for column in sorted(set(questions) - set(gaps)):
        if column in by_name:
            problems.append(
                f"{column} carries a settling question and has no `gap` cell left to settle"
            )

    counts = {value: 0 for value in DISPOSITIONS}
    counts["gap"] = sum(len(open_rows) for open_rows in gaps.values())
    for _key, entry in placed.items():
        if entry.get("disposition") in counts:
            counts[entry["disposition"]] += 1
    summary = (
        f"matrix-gate: ok — {len(rows)} P0-family properties × {len(cols)} build"
        f" configurations = {len(rows) * len(cols)} cells"
        f" ({', '.join(f'{counts[v]} {v}' for v in DISPOSITIONS)})"
    )
    return problems, summary


def check_chains(placed):
    """Every `equivalent` cell, followed until it reaches evidence or does not.

    An equivalence is a claim ABOUT another column: it inherits that column's
    disposition for the same property, and one step is not where that ends. A
    chain into a `gap` reaches nobody's judgement (`abrobot-4m` = `abrobot-16m`,
    whose own cells are undecided) and a closed one never reaches anything at all
    (`firmware-2mb` = `firmware-16mb` = `firmware-2mb`). Both were EXIT=0.
    """
    problems = []
    for (pid, column), entry in placed.items():
        if entry.get("disposition") != "equivalent":
            continue
        seen, at = [column], entry.get("same_as")
        while True:
            if at in seen:
                problems.append(
                    f"{pid} × {column}: the `same_as` chain closes on itself"
                    f" ({' -> '.join(str(c) for c in [*seen, at])}) and reaches no evidence"
                )
                break
            seen.append(at)
            step = placed.get((pid, at))
            if step is None:
                problems.append(
                    f"{pid} × {column}: `same_as` reaches {pid} × {at}, which is a `gap`"
                    " — an equivalence to a cell nobody decided is undecided too"
                )
                break
            if step.get("disposition") == "equivalent":
                at = step.get("same_as")
                continue
            if step.get("disposition") != "covered":
                problems.append(
                    f"{pid} × {column}: `same_as` reaches a `{step.get('disposition')}`"
                    f" cell at {pid} × {at} — an equivalence carries that column's"
                    " disposition, so say THAT one here rather than pointing at it"
                )
            break
    return problems


def check_cell(root, pid, column, entry, by_name, own):
    """Every way one cell's disposition disagrees with the tree."""
    where = f"{pid} × {column.name}"
    problems = []
    disposition, basis = entry.get("disposition"), entry.get("basis")
    if disposition not in DECLARABLE:
        problems.append(
            f"{where}: disposition `{disposition}` is not one of {DECLARABLE}"
            + (" — a gap is the ABSENCE of a cell here, and declaring one takes the"
               " column out of the rule that makes it owe a settling question"
               if disposition == "gap" else "")
        )
        return problems
    if len(entry.get("why", "").split()) < FLOOR_WORDS:
        problems.append(
            f"{where}: a disposition with no reason is not one — `why` is under"
            f" {FLOOR_WORDS} words"
        )
    if basis not in BASES:
        problems.append(f"{where}: basis `{basis}` is not one of {BASES}")
        return problems
    if basis not in ALLOWED[disposition]:
        problems.append(
            f"{where}: `{disposition}` may rest on {list(ALLOWED[disposition])} and this"
            f" cell says `{basis}` — a basis the tree cannot disagree with is how a"
            " judgement nobody made takes the strongest word in the vocabulary"
        )
        return problems
    if basis == SAME_FEATURES:
        other = by_name.get(entry.get("same_as"))
        if other is None:
            problems.append(f"{where}: basis `{basis}` names no column in `same_as`")
        elif other.name == column.name:
            problems.append(f"{where}: `same_as` names its own column")
        elif other.closure != column.closure or other.present != column.present:
            differs = sorted(
                crate
                for crate in other.present | column.present
                if other.closure.get(crate) != column.closure.get(crate)
                or (crate in other.present) != (crate in column.present)
            )
            problems.append(
                f"{where}: claims to compile like {other.name}, and {differs} compile"
                " differently — an equivalence the tree refutes"
            )
        else:
            problems.extend(check_knobs(where, column, other, entry))
    if basis == CRATE_ABSENT:
        here = sorted(own.get(pid, frozenset()) & column.present)
        if here:
            problems.append(
                f"{where}: claims {pid}'s owners are absent, and {here} are compiled in"
            )
        elif not own.get(pid):
            problems.append(
                f"{where}: claims {pid}'s owners are absent and no production Rust owns"
                " it at all, so the claim is about nothing"
            )
    if basis == GATE_COMPILED_OUT:
        problems.extend(check_gate(root, where, pid, column, entry, own))
    if basis == DEFAULT_BUILD and not column.default:
        problems.append(
            f"{where}: basis `{basis}` on a column that enables {sorted(column.features)}"
            f" and sets {sorted(column.knobs)}"
        )
    if basis == CHECK_SH_ROWS:
        problems.extend(check_evidence(root, where, pid, column, entry, own))
    return problems


def check_gate(root, where, pid, column, entry, own):
    """A compiled-out gate, held to the switch the cell says was thrown.

    That the feature exists is not the claim — the claim is that THIS property's
    gate is what went. Eight store and boot rows declared out-of-scope on
    `firmware-fips` with `feature = "fips-profile"` passed on nothing more than
    some production Rust somewhere gating on that feature. So the cell names the
    `cfg` site(s), each one has to really gate on the feature, and each has to
    sit in the property's blast radius: a crate whose Rust carries the property's
    tag, or `firmware`, which is the glue wiring every applet and where a
    presence switch like `no-touch` actually lives.
    """
    feature = entry.get("feature")
    if feature not in column.features:
        return [
            f"{where}: basis `{GATE_COMPILED_OUT}` names `{feature}`,"
            " which this column does not enable"
        ]
    gating = {str(path.relative_to(root)) for path in cfg_sites(root, feature)}
    if not gating:
        return [
            f"{where}: basis `{GATE_COMPILED_OUT}` names `{feature}`,"
            " and no production Rust gates on it"
        ]
    named = entry.get("cfg") or []
    if not named:
        return [
            f"{where}: basis `{GATE_COMPILED_OUT}` and no `cfg` — the tree gates on"
            f" `{feature}` in {sorted(gating)}, and which of those is {pid}'s gate is"
            " the whole claim"
        ]
    problems, carries = [], own.get(pid, frozenset())
    for site in named:
        if site not in gating:
            problems.append(
                f"{where}: names `{site}`, which does not gate on `{feature}` —"
                f" the tree's sites are {sorted(gating)}"
            )
            continue
        crate = site.split("/")[1] if site.startswith("crates/") else "firmware"
        if crate not in carries | {"firmware"}:
            problems.append(
                f"{where}: `{site}` gates on `{feature}` in `{crate}`, and {pid} is"
                f" carried by {sorted(carries)} — that switch is another property's gate"
            )
    return problems


def check_evidence(root, where, pid, column, entry, own):
    """The `check.sh` rows a `covered` cell names, held to the cell it is under.

    Two things, and both are needed. A row is about this COLUMN only if it builds
    this column — the same cargo features and the same build knobs; features
    alone are vacuously equal on the six board presets and on every column whose
    delta is geometry, which is most of them. And a row is about this PROPERTY
    only if it selects a crate whose production Rust carries the property's tag:
    without that half, a row that merely COMPILES the image counted, and
    `build firmware (test, --features no-touch)` re-declared the four presence
    statements `covered` on the very image that removes their gate.

    What it still cannot say is whether the row MEASURES the property rather than
    building it — that is the `why`'s job, as everywhere else in this file.
    """
    named = entry.get("evidence") or []
    if not named:
        return [
            f"{where}: basis `{CHECK_SH_ROWS}` and no `evidence` — name the rows that"
            " produced it, or the claim is the prose basis this vocabulary dropped"
        ]
    rows, problems, runs_owner = check_sh_rows(root), [], False
    for label in named:
        if label not in rows:
            problems.append(f"{where}: names `{label}`, which is no {CHECK} row")
            continue
        features, env, command = rows[label]
        if features != column.features:
            problems.append(
                f"{where}: `{label}` builds {sorted(features)} and this column is"
                f" {sorted(column.features)} — evidence from another image"
            )
        open_knobs = unpinned_knobs(column, env)
        if open_knobs:
            problems.append(
                f"{where}: `{label}` does not pin {open_knobs} — the row ran at other"
                " build knobs than this column's, so it measured another image"
            )
        runs_owner |= bool(own.get(pid, frozenset()) & gate_lines.packages(command))
    if not runs_owner and not problems:
        problems.append(
            f"{where}: no row named here selects {sorted(own.get(pid, frozenset()))},"
            f" the crate(s) whose production Rust carries {pid} — a row that compiles"
            " this image is not evidence about this property"
        )
    return problems


def unpinned_knobs(column, env):
    """The column's build knobs a row leaves at some other value, as `KEY=value`."""
    if column.kind == "board":
        return [] if env.get("BOARD") == column.name else [f"BOARD={column.name}"]
    return sorted(
        f"{env_name(key)}={value}"
        for key, value in column.knobs.items()
        if env.get(env_name(key)) != value
    )


def knob_delta(column, other):
    """The build knobs the two columns do not agree on, as `key=value`.

    With the VALUE, because the names alone cannot see the edit that matters:
    `waveshare-one` earns its equivalence by setting seven knobs to the values
    `build.rs` already defaults to, and moving its `flash.size_mb` from 4 to 16
    leaves the name list identical. No attempt is made to reconcile the two
    spellings of one knob (a flake argument `flashSize`, a board key
    `flash.size_mb`) — that would be a mapping table going stale beside
    `build.rs`, and both spellings reaching the reader is the honest answer.
    """
    return sorted(
        f"{key}={column.knobs.get(key, '')}"
        for key in set(column.knobs) | set(other.knobs)
        if column.knobs.get(key) != other.knobs.get(key)
    )


def check_knobs(where, column, other, entry):
    """The half of an equivalence the feature closure cannot see.

    Every `same-cargo-features` cell in this tree compares an empty feature set
    with an empty one — that is what "the delta is knobs" MEANS — so without this
    the row's one machine-checked rule was vacuous on all of them. The knobs are
    compile-time: `build.rs` turns them into `rustc-env` constants, two
    `rustc-cfg` values and a regenerated `memory.x`.
    """
    if len(entry.get("columns", [])) != 1:
        return [
            f"{where}: an `equivalent` cell names {len(entry['columns'])} columns —"
            " the knob delta is per column, so each one is its own cell"
        ]
    derived = knob_delta(column, other)
    declared = entry.get("knob_delta")
    if declared is None:
        return [
            f"{where}: an `equivalent` on identical cargo features owes a"
            f" `knob_delta`; the tree derives {derived}"
        ]
    if sorted(declared) != derived:
        return [
            f"{where}: declares the knob delta {sorted(declared)} and the tree"
            f" derives {derived} — re-decide the cell, do not re-label it"
        ]
    return []


@functools.cache
def cfg_sites(root, feature):
    """The production files that gate on `feature` — the switch's existence.

    Production, on the same rule `owners` uses: a `cfg` in a `*_tests.rs` or a
    Kani harness is not a gate in the image, and a cell that named one would be
    pointing at code the firmware never runs.
    """
    if not feature:
        return []
    pattern = re.compile(rf'feature\s*=\s*"{re.escape(feature)}"')
    files = [*(root / "crates").glob("*/src/**/*.rs"), *(root / "firmware/src").glob("**/*.rs")]
    return [
        path
        for path in sorted(files)
        if "kani" not in path.name
        and "tests" not in path.name
        and pattern.search(path.read_text(errors="ignore"))
    ]


# --- the artifact -----------------------------------------------------------


def render(root):
    """`docs/assurance-matrix.md` as the derivation and the ledger make it."""
    manifests = workspace(root)
    cols = columns(root, manifests)
    doc = ledger(root)
    entries = registry(root)
    ids = [pid for pid, _name in entries]
    names = dict(entries)
    tranche = {
        pid: name for name in TRANCHES for pid in doc.get("tranche", {}).get(name, [])
    }
    rows = [pid for pid in ids if tranche.get(pid) in ROW_TRANCHES]
    placed = dict(expand(doc, []))
    questions = {q["column"]: q["text"] for q in doc.get("question", [])}

    out = [
        "<!-- SPDX-License-Identifier: AGPL-3.0-only -->",
        "<!-- Copyright (C) 2026 RS-Key contributors -->",
        f"<!-- {GENERATED_BY} — do not edit by hand -->",
        "",
        "# Assurance matrix",
        "",
        "Which security property is claimed about which buildable image. The rows are"
        " the P0-family properties of `assurance/properties.toml`; the columns are"
        " derived from `nix/firmware.nix`, `firmware/Cargo.toml` and"
        " `firmware/boards/`, so a new package, feature or board arrives as a column"
        " of `gap` cells rather than as silence. `scripts/matrix_gate.py` regenerates"
        " this page and `scripts/check.sh` diffs it.",
        "",
        "The point of the page is the thing a single-build claim hides: **the firmware"
        " is not one thing.** Four of the nineteen images remove the physical-consent"
        " gate the authorization properties are about, one swaps the CTAP large-blob"
        " surface with no flake package at all, and the board axis changes the flash"
        " geometry on which a whole KV store once survived a \"successful\" wipe.",
        "",
        "| Disposition | Code | Means |",
        "|---|---|---|",
        "| `covered` | `cov` | the evidence the registry records was produced on this configuration |",
        "| `equivalent` | `equ` | this configuration enables exactly the cargo features another does; `same_as` names it, the gate re-derives both closures, and the cell must write down the build knobs that still differ |",
        "| `conditional` | `cnd` | claimed only under a stated condition |",
        "| `out-of-scope` | `oos` | the claim is not made here — the code it is about is absent, or the gate it is about is compiled out |",
        "| `gap` | `gap` | nobody has decided yet; the column's settling question is below |",
        "",
        "## The axes",
        "",
        f"- **{len([c for c in cols if c.kind == 'package'])} flake packages**"
        f" (`nix/firmware.nix`), of which"
        f" **{len([c for c in cols if c.kind == 'package' and c.published])}** are"
        " published by `.github/workflows/release-build.yml` — the published set is a"
        " named subset of the matrix, never the matrix.",
        f"- **{len([c for c in cols if c.kind == 'feature'])} orthogonal cargo features**"
        " (`firmware/Cargo.toml`) that no flake package expresses.",
        f"- **{len([c for c in cols if c.kind == 'board'])} board presets**"
        " (`firmware/boards/*.toml`): `BOARD=<name>` sets the same knobs the flake"
        " arguments do, and no cargo feature.",
        "",
        "## Columns",
        "",
        "| # | Configuration | Kind | Published | Cargo features | Knobs |",
        "|---|---|---|---|---|---|",
    ]
    index = {column.name: f"{n:02d}" for n, column in enumerate(cols, 1)}
    for column in cols:
        feats = ", ".join(f"`{f}`" for f in sorted(column.features)) or "—"
        knobs = ", ".join(f"`{k}={v}`" for k, v in sorted(column.knobs.items())) or "—"
        flag = "yes" if column.published else ("n/a" if column.kind != "package" else "no")
        out.append(
            f"| {index[column.name]} | `{column.name}` | {column.kind} | {flag} | {feats} | {knobs} |"
        )

    out += [
        "",
        "## The matrix",
        "",
        f"{len(rows)} rows × {len(cols)} columns = {len(rows) * len(cols)} cells."
        " Column numbers are the table above.",
        "",
        "| Property | " + " | ".join(index[c.name] for c in cols) + " |",
        "|---" * (len(cols) + 1) + "|",
    ]
    for pid in rows:
        line = [f"`{pid}`"]
        for column in cols:
            entry = placed.get((pid, column.name))
            line.append(CODE[entry["disposition"]] if entry else CODE["gap"])
        out.append("| " + " | ".join(line) + " |")

    out += ["", "## Dispositions", ""]
    for entry in doc.get("cell", []):
        cs = ", ".join(f"`{c}`" for c in entry["columns"])
        ps = ", ".join(f"`{p}`" for p in entry["properties"])
        extra = ""
        if entry.get("same_as"):
            knobs = ", ".join(f"`{k}`" for k in entry.get("knob_delta", [])) or "none"
            extra = f" (`same_as = {entry['same_as']}`; knob delta: {knobs})"
        elif entry.get("feature"):
            sites = ", ".join(f"`{s}`" for s in entry.get("cfg", [])) or "none"
            extra = f" (`feature = {entry['feature']}`; gate: {sites})"
        out += [
            f"**{entry['disposition']}** — basis `{entry['basis']}`{extra}",
            "",
            f"- columns: {cs}",
            f"- properties: {ps}",
            f"- {entry['why']}",
            "",
        ]

    out += ["## Open gaps", "", "| Configuration | `gap` rows | The question that would settle them |", "|---|---|---|"]
    for column in cols:
        open_rows = [pid for pid in rows if (pid, column.name) not in placed]
        if open_rows:
            out.append(
                f"| `{column.name}` | {len(open_rows)} | {questions.get(column.name, '')} |"
            )

    out += [
        "",
        "## Property names",
        "",
        "| ID | Invariant | Tranche |",
        "|---|---|---|",
    ]
    for pid in rows:
        out.append(f"| `{pid}` | `{names[pid]}` | {tranche[pid]} |")
    return "\n".join(out) + "\n"


def run(root, write=False):
    root = pathlib.Path(root)
    if write:
        (root / ARTIFACT).write_text(render(root))
        print(f"matrix-gate: wrote {ARTIFACT}")
        return 0
    try:
        problems, summary = audit(root)
    except (*MALFORMED, ValueError) as error:
        problems, summary = [f"the axes cannot be derived from the tree: {error}"], ""
    # Always, not only on an otherwise-clean ledger: a new package arrives as a
    # column of gaps AND a stale artifact, and the reader who has to regenerate
    # should be told so in the same run rather than on the next one.
    try:
        want = render(root)
    except (*MALFORMED, ValueError) as error:
        problems.append(f"{ARTIFACT} cannot be generated from {LEDGER}: {error}")
    else:
        # Bytes, not text: `read_text` folds `\r\n` to `\n`, so a CRLF copy
        # compared as text is equal to a LF one — the lesson `config_gen_gate.py`
        # already wrote down, in the very file this row names as its model.
        got = (root / ARTIFACT).read_bytes() if (root / ARTIFACT).is_file() else b""
        if want.encode() != got:
            problems.append(
                f"{ARTIFACT} is not what the generator writes — run"
                " `python scripts/matrix_gate.py --write` and commit the result"
            )
    if problems:
        print(f"matrix-gate: {len(problems)} finding(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEvery P0-family property owes each buildable configuration a"
            " disposition:\ncovered, equivalent, conditional, out-of-scope or gap."
            f" Decide the cell in\n{LEDGER}; a claim about \"the firmware\" that is"
            " true of one image\nand untested on eighteen others is the failure this row"
            " is for.",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


def main():
    argv = sys.argv[1:]
    if argv and argv != ["--write"]:
        print("usage: matrix_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    sys.exit(main())
