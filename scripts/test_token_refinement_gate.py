# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Mutation table for the phase-5 concrete-event completeness gate."""

from pathlib import Path

import pytest

import token_refinement_gate


EXPORT = """TOKEN|OP|IssueToken
TOKEN|OP|SetPin
TOKEN|OP|UseMc
"""

MANIFEST = """[[volatile_writer]]
file = "crates/rsk-fido/src/state.rs"
function = "issue"
op = "IssueToken"

[[persistent_writer]]
file = "crates/rsk-fido/src/state.rs"
function = "persist"
op = "SetPin"

[[outcome_producer]]
file = "crates/rsk-fido/src/state.rs"
function = "authorize"
op = "UseMc"

[[walk_owner]]
file = "crates/rsk-fido/src/state.rs"
function = "may_walk_rps"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"

[[softlock_owner]]
file = "crates/rsk-fido/src/state.rs"
function = "pin_lock"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"

[[softlock_owner]]
file = "crates/rsk-fido/src/state.rs"
function = "restore_pin_lock"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"

[[reset_window_owner]]
file = "crates/rsk-fido/src/reset.rs"
function = "in_reset_window"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"
"""

STATE = """pub const PERM_MC: u8 = 0x01;
pub const PERM_LBW: u8 = 0x10;
pub const PERM_ACFG: u8 = 0x20;

pub struct PinUvAuthToken {
    pub token: [u8; 32],
    pub in_use: bool,
    pub permissions: u8,
    pub rp_id_hash: [u8; 32],
    pub has_rp_id: bool,
    pub last_used_ms: u64,
}

fn issue() {
    state.paut.in_use = true;
}

fn persist() {
    fs.put(EF_PIN, &[]);
}

fn authorize() {
    let authorized = state.paut.permissions & PERM_MC != 0;
}

pub struct PinLock {
    pub engaged: bool,
    pub mismatches: u8,
}

pub fn may_walk_rps(&self, channel: u32) -> bool {
    self.channel == channel && self.rp_counter <= self.rp_total
}

pub fn pin_lock(&self) -> PinLock {
    PinLock {
        engaged: self.needs_power_cycle,
        mismatches: self.new_pin_mismatches,
    }
}

pub fn restore_pin_lock(&mut self, lock: PinLock) {
    self.needs_power_cycle = lock.engaged;
}
"""

# The reset window's guard, in the file the derivation reads it out of.
RESET = """fn in_reset_window(ctx: &Ctx) -> bool {
    !ctx.state.warm_boot && ctx.now_ms <= RESET_WINDOW_MS
}
"""

PROJECTION = """pub const TOKEN_PERSISTENT_FIDS: [u16; 2] =
    [crate::consts::EF_PIN, crate::consts::EF_PAUTHTOKEN.get()];

impl FidoState {
    pub fn abstract_token(&self, persistent: TokenPersistentView) -> AState {
        AState {
            live: self.paut.in_use,
            permission_mc: self.paut.permissions & PERM_MC != 0,
            permission_acfg: self.paut.permissions & PERM_ACFG != 0,
            rp_bound: self.paut.has_rp_id,
        }
    }
}
"""

CONSTS = """pub const EF_PIN: u16 = 0x1080;
pub const EF_PAUTHTOKEN: KeyFid = KeyFid::new(0x1091);
"""

LIB = """pub mod state;
pub mod consts;
pub mod state_assurance;

#[cfg(test)]
mod harness;
"""

# Only the shape the gate reads: which public methods reach a storage mutation.
STORE = """impl<S: Storage> Fs<S> {
    pub fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.storage.read(fid, buf)
    }

    pub fn put(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.storage.write(fid, data)
    }

    pub fn delete(&mut self, fid: u16) -> Result<()> {
        self.storage.remove(fid)
    }

    pub fn delete_key(&mut self, fid: KeyFid) -> Result<()> {
        self.delete(fid.get())
    }
}
"""

MATRIX = """| # | Configuration | Kind | Published |
|---|---|---|---|
| 01 | `firmware` | package | yes |
| 16 | `firmware-display` | package | yes |
| 25 | `largeblob-ext` | feature | n/a |
"""


class Tree:
    def __init__(self, root: Path):
        self.root = root
        self.write("formal/generated/token_relation.txt", EXPORT)
        self.write("assurance/token_refinement.toml", MANIFEST)
        self.write("crates/rsk-fido/src/lib.rs", LIB)
        self.write("crates/rsk-fido/src/state.rs", STATE)
        self.write("crates/rsk-fido/src/reset.rs", RESET)
        self.write("crates/rsk-fido/src/consts.rs", CONSTS)
        self.write("crates/rsk-fido/src/state_assurance.rs", PROJECTION)
        self.write("crates/rsk-fido/src/harness.rs", "")
        self.write("crates/rsk-fs/src/fs.rs", STORE)
        self.write("docs/assurance-matrix.md", MATRIX)

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def append(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.write_text(path.read_text() + text)

    def replace(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text()
        assert text.count(old) == 1
        path.write_text(text.replace(old, new))

    def own(self, category: str, function: str, extra: str = "", file: str = None) -> None:
        self.append(
            "assurance/token_refinement.toml",
            f'\n[[{category}]]\nfile = "{file or "crates/rsk-fido/src/state.rs"}"\n'
            f'function = "{function}"\n{extra}',
        )

    def findings(self) -> list[str]:
        """The gate over this fixture, with the floors scaled to it.

        The floors are calibrated on the real tree — 4 walk sites, 12 soft-lock,
        2 window — and this tree carries one family member each on purpose: the
        arms below are about the RULES, and a floor written for the checkout
        would make every one of them red for the fixture's size. The floors
        themselves are falsified against the real numbers in
        `test_a_derivation_that_finds_nothing_trips_its_own_floor`.
        """
        was = token_refinement_gate.FLOORS
        token_refinement_gate.FLOORS = dict.fromkeys(token_refinement_gate.AXES, 1)
        try:
            return token_refinement_gate.audit(self.root)[0]
        finally:
            token_refinement_gate.FLOORS = was


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


def contains(findings: list[str], text: str) -> bool:
    return any(text in finding for finding in findings)


def only(findings: list[str], text: str) -> bool:
    """The finding is there AND it is the only one — a direction check.

    Half the arms below add a site and assert one message; without this the arm
    passes on a fixture that went red for an unrelated reason, which is the
    failure mode this repo has measured twice.
    """
    return len(findings) == 1 and text in findings[0]


def test_green_fixture_passes(tree: Tree):
    assert tree.findings() == []


def test_this_checkout_passes():
    assert token_refinement_gate.audit(token_refinement_gate.ROOT)[0] == []


def test_an_owner_cannot_name_an_operation_outside_tla(tree: Tree):
    tree.replace("assurance/token_refinement.toml", 'op = "IssueToken"', 'op = "Unknown"')
    assert only(tree.findings(), "Unknown is outside the generated TLA+ Ops domain")


def test_the_persistent_domain_is_derived_from_the_projection(tree: Tree):
    tree.replace("crates/rsk-fido/src/state_assurance.rs", "EF_PAUTHTOKEN", "EF_ALWAYS_UV")
    assert contains(tree.findings(), "TokenPersistentView key derivation yielded")


@pytest.mark.parametrize(
    ("body", "finding"),
    [
        ("fn stray() { state.paut.permissions = 0; }\n", "volatile: unowned concrete site"),
        # `|=` and the in-place array writes: the first regex knew `=` and `&=`,
        # and knew three of the nine fields.
        ("fn stray() { state.paut.permissions |= 1; }\n", "volatile: unowned concrete site"),
        (
            "fn stray() { state.paut.rp_id_hash.copy_from_slice(&h); }\n",
            "volatile: unowned concrete site",
        ),
        ("fn stray() { fs.delete(EF_PIN); }\n", "persistent: unowned concrete site"),
        # `delete_key` is a token-record write the hand-written four could not see:
        # the alternation `put|put_key|delete|force_delete` matched `delete` and
        # then demanded `(`.
        ("fn stray() { fs.delete_key(EF_PAUTHTOKEN); }\n", "persistent: unowned concrete site"),
        (
            "fn stray() { let ok = state.paut.permissions & PERM_ACFG != 0; }\n",
            "outcome: unowned concrete site",
        ),
        # A permission outside the four the abstraction reads is still a gate.
        (
            "fn stray() { let ok = state.paut.permissions & PERM_LBW != 0; }\n",
            "outcome: unowned concrete site",
        ),
        # The MAC without the mask — the bypass shape the permission query alone
        # cannot see.
        ("fn stray() { if !state.verify_token(p, d, m) { fail(); } }\n", "outcome: unowned"),
        # Every shape below was written by an adversarial review of this gate and
        # was NOT flagged when it ran. A receiver is an expression, not one word.
        ("fn stray() { let _ = Fs::put(&mut ctx.fs, EF_PIN, &[]); }\n", "persistent: unowned"),
        ("fn stray() { let _ = Fs::delete(c.fs, EF_PIN); }\n", "persistent: unowned"),
        # The fid as the number the constant is defined as.
        ("fn stray() { let _ = fs.delete(0x1080); }\n", "persistent: unowned"),
        ("fn stray() { let _ = fs.delete_key(0x1091); }\n", "persistent: unowned"),
        # Replacing the whole token, which touches no `.paut.<field>` at all.
        ("fn stray(s: &mut S) { let _ = mem::take(&mut s.paut); }\n", "volatile: unowned"),
        ("fn stray(s: &mut S) { mem::swap(&mut s.paut, o); }\n", "volatile: unowned"),
        ("fn stray(s: &mut S) { let t = &mut s.paut; t.in_use = true; }\n", "volatile: unowned"),
        # A parenthesised permission set, and the primitive called as a path.
        ("fn stray(s: &S) -> bool { s.paut.permissions & (PERM_ACFG | PERM_MC) != 0 }\n", "outcome: unowned"),
        ("fn stray(s: &S) -> bool { PERM_ACFG & s.paut.permissions != 0 }\n", "outcome: unowned"),
        ("fn stray(s: &S) -> bool { FidoState::verify_token(s, p, d, m) }\n", "outcome: unowned"),
        # The six in-place mutators beside `copy_from_slice`.
        ("fn stray(s: &mut S) { s.paut.rp_id_hash.fill(0); }\n", "volatile: unowned"),
    ],
)
def test_an_unowned_concrete_site_fails(tree: Tree, body: str, finding: str):
    tree.append("crates/rsk-fido/src/state.rs", body)
    assert only(tree.findings(), finding)


def test_a_const_fn_body_is_not_charged_to_the_function_above_it(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "const fn stray() { state.paut.in_use = false; }\n",
    )
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::stray")


@pytest.mark.parametrize(
    "body",
    [
        # A commented-out write. `= TRUE \\* comment` cost this programme a green
        # run over a dead model assumption; this is the same shape in Rust.
        "fn stray() {\n    // let _ = fs.put(EF_PIN, &[]);\n    let _ = fs.put(other, &[]);\n}\n",
        # A predicate that names the fid in prose only. `reset()` really does
        # mention EF_PIN in a comment and hands predicates to `sweep`, so reading
        # comments as code invents a writer out of the pairing.
        "fn wipe(pred: fn(u16) -> bool) { fs.delete(fid); }\n\n"
        "fn owns(fid: u16) -> bool {\n    // reaches EF_PIN before the credentials\n    false\n}\n\n"
        "fn stray() { wipe(owns); }\n",
    ],
)
def test_a_fid_named_only_in_a_comment_is_not_a_writer(tree: Tree, body: str):
    tree.append("crates/rsk-fido/src/state.rs", body)
    assert tree.findings() == []


def test_a_caller_that_hands_a_token_fid_to_a_generic_writer_is_a_site(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn helper(fid: u16) { fs.put(fid, &[]); }\n\nfn stray() { helper(EF_PIN); }\n",
    )
    findings = tree.findings()
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::helper")


def test_a_predicate_that_names_a_token_fid_reaches_the_sweep_it_selects(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn wipe(pred: fn(u16) -> bool) { fs.delete(fid); }\n\n"
        "fn owns(fid: u16) -> bool { fid == EF_PIN }\n\n"
        "fn stray() { wipe(owns); }\n",
    )
    findings = tree.findings()
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::wipe")
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")


@pytest.mark.parametrize(
    ("category", "finding"),
    [
        ("volatile_writer", "volatile: stale owner"),
        ("persistent_writer", "persistent: stale owner"),
        ("outcome_producer", "outcome: stale owner"),
    ],
)
def test_a_stale_manifest_owner_fails(tree: Tree, category: str, finding: str):
    tree.own(category, "gone", 'op = "UseMc"\n')
    assert only(tree.findings(), finding)


def test_a_generic_flag_does_not_excuse_a_stale_owner(tree: Tree):
    tree.own("persistent_writer", "gone", 'op = "SetPin"\ngeneric = true\n')
    assert contains(tree.findings(), "persistent: stale owner")


def _own_the_helper_pair(tree: Tree, on_caller: str, on_helper: str) -> None:
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn helper(fid: u16) { fs.put(fid, &[]); }\n\nfn stray() { helper(EF_PIN); }\n",
    )
    tree.own("persistent_writer", "stray", f'op = "SetPin"\n{on_caller}')
    tree.own("persistent_writer", "helper", f'op = "SetPin"\n{on_helper}')


def test_a_helper_that_writes_a_handed_fid_must_say_so(tree: Tree):
    _own_the_helper_pair(tree, "", "")
    assert only(tree.findings(), "state.rs::helper does write a fid it was handed")


def test_a_caller_that_only_names_the_fid_may_not_claim_to_be_generic(tree: Tree):
    _own_the_helper_pair(tree, "generic = true\n", "generic = true\n")
    assert only(tree.findings(), "state.rs::stray does not write a fid it was handed")


def test_a_writer_the_abstraction_cannot_see_may_not_be_a_step(tree: Tree):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.last_used_ms = t; }\n")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n')
    assert only(tree.findings(), "is a step over state the abstraction cannot see")


def test_a_writer_the_abstraction_does_see_may_not_be_a_stutter(tree: Tree):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.in_use = false; }\n")
    tree.own("volatile_writer", "stray", 'disposition = "stutter"\nwhy = "no"\n')
    assert only(tree.findings(), "writes abstract state and is not a step")


@pytest.mark.parametrize(
    ("extra", "finding"),
    [
        ('disposition = "elsewhere"\n', "carries disposition 'elsewhere'"),
        ('disposition = "stutter"\nop = "IssueToken"\nwhy = "x"\n', "and still names an op"),
        ('disposition = "stutter"\n', "is stutter with no reason"),
        ('disposition = "out-of-scope"\nwhy = "   "\n', "is out-of-scope with no reason"),
    ],
)
def test_a_disposition_must_be_answerable(tree: Tree, extra: str, finding: str):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.last_used_ms = t; }\n")
    tree.own("volatile_writer", "stray", extra)
    assert contains(tree.findings(), finding)


def test_a_cfg_test_module_must_declare_itself(tree: Tree):
    tree.write("crates/rsk-fido/src/harness.rs", "fn stray() { state.paut.in_use = true; }\n")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n', file="crates/rsk-fido/src/harness.rs")
    assert only(tree.findings(), "harness.rs::stray is compiled only under cfg(test)")


def test_a_production_module_may_not_claim_to_be_test_only(tree: Tree):
    tree.replace("assurance/token_refinement.toml", 'op = "IssueToken"', 'op = "IssueToken"\ntest_only = true')
    assert only(tree.findings(), "state.rs::issue is not compiled only under cfg(test)")


def test_the_module_graph_and_not_the_file_name_decides(tree: Tree):
    """Unhooking `mod harness;` makes the same file production again."""
    tree.write("crates/rsk-fido/src/harness.rs", "fn stray() { state.paut.in_use = true; }\n")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n', file="crates/rsk-fido/src/harness.rs")
    tree.replace("crates/rsk-fido/src/lib.rs", "#[cfg(test)]\nmod harness;", "mod harness;")
    assert tree.findings() == []


@pytest.mark.parametrize(
    ("extra", "finding"),
    [
        ('op = "IssueToken"\ncolumn = "firmware-nope"\nwhy = "x"\n', "which the matrix has no column for"),
        ('op = "IssueToken"\ncolumn = "largeblob-ext"\n', "configuration-conditional with no reason"),
    ],
)
def test_a_column_comes_from_the_matrix(tree: Tree, extra: str, finding: str):
    tree.replace("assurance/token_refinement.toml", 'op = "IssueToken"\n', extra)
    assert only(tree.findings(), finding)


def test_a_token_record_written_outside_rsk_fido_fails(tree: Tree):
    tree.write(
        "crates/rsk-device/src/ctap.rs",
        "use rsk_fido::consts::{EF_PAUTHTOKEN, EF_PIN};\n\nfn stray() { fs.delete(EF_PIN); }\n",
    )
    assert only(tree.findings(), "foreign: unowned concrete site crates/rsk-device/src/ctap.rs::stray")


def test_another_applets_like_named_record_is_not_this_one(tree: Tree):
    """`rsk-piv` defines its own `EF_PIN` (0xD180), and writes it constantly."""
    tree.write(
        "crates/rsk-piv/src/files.rs",
        "pub const EF_PIN: u16 = 0xD180;\n\nfn stray() { fs.put(EF_PIN, &[]); }\n",
    )
    assert tree.findings() == []


def test_the_store_write_api_is_read_out_of_the_store(tree: Tree):
    """A new `Fs` mutator is a new way to write a token record, with no edit here."""
    tree.append(
        "crates/rsk-fs/src/fs.rs",
        "\nimpl<S: Storage> Fs<S> {\n    pub fn scribble(&mut self, fid: u16) -> Result<()> {\n"
        "        self.storage.write(fid, &[])\n    }\n}\n",
    )
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { fs.scribble(EF_PIN); }\n")
    assert only(tree.findings(), "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_test_kani_and_generated_files_are_not_production_axes(tree: Tree):
    body = "fn ignored() { state.paut.in_use = true; fs.delete(EF_PIN); }\n"
    tree.write("crates/rsk-fido/src/state_tests.rs", body)
    tree.write("crates/rsk-fido/src/state_kani.rs", body)
    tree.write("crates/rsk-fido/src/generated_token_edges.rs", body)
    assert tree.findings() == []


def test_main_prints_a_nonempty_success_summary(tree: Tree, monkeypatch, capsys):
    monkeypatch.setattr(token_refinement_gate, "ROOT", tree.root)
    monkeypatch.setattr(
        token_refinement_gate, "FLOORS", dict.fromkeys(token_refinement_gate.AXES, 1)
    )
    assert token_refinement_gate.main() == 0
    assert capsys.readouterr().out.startswith("token-refinement-gate: GREEN")


def test_main_reports_every_finding_and_exits_nonzero(tree: Tree, monkeypatch, capsys):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.in_use = true; }\n")
    monkeypatch.setattr(token_refinement_gate, "ROOT", tree.root)
    monkeypatch.setattr(
        token_refinement_gate, "FLOORS", dict.fromkeys(token_refinement_gate.AXES, 1)
    )
    assert token_refinement_gate.main() == 1
    assert "unowned concrete site" in capsys.readouterr().err


def test_replacing_the_whole_state_is_a_token_write(tree: Tree):
    """`FidoState::reset` is `*self = Self::new()` — every abstract bit at once."""
    tree.append("crates/rsk-fido/src/state.rs", "fn stray(&mut self) { *self = Self::new(); }\n")
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_replacing_the_whole_state_cannot_be_a_stutter(tree: Tree):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray(&mut self) { *self = Self::new(); }\n")
    tree.own("volatile_writer", "stray", 'disposition = "stutter"\nwhy = "no"\n')
    assert only(tree.findings(), "writes abstract state and is not a step")


@pytest.mark.parametrize(
    "desync",
    [
        "fn spacer() { let _b = '{'; }\n",
        "fn spacer() { /* { */ }\n",
        'fn spacer() { let _s = "}"; }\n',
    ],
)
def test_a_brace_inside_a_literal_does_not_swallow_the_next_writer(tree: Tree, desync: str):
    """One char literal desynchronises the depth counter, and every writer after
    it in the file joins the previous function's body — silently."""
    tree.append("crates/rsk-fido/src/state.rs", desync)
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.in_use = true; }\n")
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_a_writer_written_inside_a_string_is_not_a_writer(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        'fn stray() { log("fs.put(EF_PIN, &[]) and paut.in_use = true"); }\n',
    )
    assert tree.findings() == []


def test_a_nested_fn_belongs_to_the_function_that_contains_it(tree: Tree):
    """Bodies close on brace depth, so `inner` is part of `outer` — the run-to-the-
    next-`fn` form reports `inner` instead, and this is what tells them apart."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn outer() {\n    fn inner() { state.paut.in_use = true; }\n}\n",
    )
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::outer")


@pytest.mark.parametrize("spelling", ["pub fn", "pub(crate) fn", "pub async fn"])
def test_every_public_spelling_of_a_store_mutator_counts(tree: Tree, spelling: str):
    """`pub(crate) fn` appears 149 times in this tree; a second, narrower `pub fn`
    pattern here would drop such a method out of the derived write API in silence."""
    tree.append(
        "crates/rsk-fs/src/fs.rs",
        f"\nimpl<S: Storage> Fs<S> {{\n    {spelling} scribble(&mut self, fid: u16) -> Result<()> {{\n"
        "        self.storage.write(fid, &[])\n    }\n}\n",
    )
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { fs.scribble(EF_PIN); }\n")
    assert only(tree.findings(), "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_a_private_store_helper_is_not_part_of_the_write_api(tree: Tree):
    tree.append(
        "crates/rsk-fs/src/fs.rs",
        "\nimpl<S: Storage> Fs<S> {\n    fn scribble(&mut self, fid: u16) -> Result<()> {\n"
        "        self.storage.write(fid, &[])\n    }\n}\n",
    )
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { fs.scribble(EF_PIN); }\n")
    assert tree.findings() == []


def test_the_module_import_and_not_the_two_names_scopes_the_foreign_sweep(tree: Tree):
    tree.write(
        "crates/rsk-device/src/ctap.rs",
        "use rsk_fido::consts;\n\nfn stray() { fs.delete(consts::EF_PIN); }\n",
    )
    assert only(tree.findings(), "foreign: unowned concrete site crates/rsk-device/src/ctap.rs::stray")


def test_a_file_reached_both_gated_and_plain_is_production(tree: Tree):
    tree.write("crates/rsk-fido/src/harness.rs", "fn stray() { state.paut.in_use = true; }\n")
    tree.replace("crates/rsk-fido/src/lib.rs", "pub mod state;", "pub mod state;\npub mod harness;")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n', file="crates/rsk-fido/src/harness.rs")
    assert tree.findings() == []


# ---- the three guard axes ----------------------------------------------------


@pytest.mark.parametrize(
    "axis,removal",
    [
        ("walk", ("crates/rsk-fido/src/state.rs", "self.channel == channel", "true")),
        ("reset_window", ("crates/rsk-fido/src/reset.rs", "RESET_WINDOW_MS", "0")),
    ],
)
def test_a_derivation_that_finds_nothing_trips_its_own_floor(tree: Tree, axis, removal):
    """Every rule on an axis passes over an empty roster, which is the shape a
    verdict column cannot show. Run at the REAL floors, so what is falsified is
    the number this file ships and not a fixture-sized stand-in."""
    path, old, new = removal
    tree.replace(path, old, new)
    findings = token_refinement_gate.audit(tree.root)[0]
    assert contains(findings, f"{axis}: 0 site(s) derived, under the floor of"), findings


@pytest.mark.parametrize(
    "axis,file,function",
    [
        ("walk", "crates/rsk-fido/src/state.rs", "may_walk_rps"),
        ("softlock", "crates/rsk-fido/src/state.rs", "pin_lock"),
        ("reset_window", "crates/rsk-fido/src/reset.rs", "in_reset_window"),
    ],
)
def test_an_unowned_guard_site_fails(tree: Tree, axis, file, function):
    tree.replace(
        "assurance/token_refinement.toml", f'function = "{function}"', 'function = "gone"'
    )
    findings = tree.findings()
    assert contains(findings, f"{axis}: unowned concrete site {file}::{function}"), findings
    assert contains(findings, f"{axis}: stale owner {file}::gone"), findings


def test_a_caller_of_a_guard_is_a_site_of_its_family(tree: Tree):
    """The derivation is guards AND callers: `may_walk_rps` has one production
    caller and it is one frame out, in `credmgmt.rs`."""
    tree.write(
        "crates/rsk-fido/src/credmgmt.rs",
        "fn enumerate_rps() {\n    if !state.cm.may_walk_rps(state.channel) { return; }\n}\n",
    )
    assert only(
        tree.findings(),
        "walk: unowned concrete site crates/rsk-fido/src/credmgmt.rs::enumerate_rps",
    ), tree.findings()


def test_a_board_half_that_only_names_the_wire_type_is_a_site(tree: Tree):
    """`Hooks::store_pin_lock` calls neither guard — it takes the lock BY TYPE.
    Measured: `pin_lock` and `restore_pin_lock` have zero callers inside the
    applet, so a family derived from calls alone loses the whole board half."""
    tree.write(
        "crates/rsk-device/src/lib.rs",
        "pub mod ctap;\nfn store_pin_lock(&mut self, _lock: PinLock) {}\n",
    )
    assert only(
        tree.findings(),
        "softlock: unowned concrete site crates/rsk-device/src/lib.rs::store_pin_lock",
    ), tree.findings()


def test_the_soft_locks_fields_are_read_out_of_its_accessor(tree: Tree):
    """The two `FidoState` fields are named once in the tree, in `pin_lock`, and
    naming them here would be twice."""
    tree.replace(
        "crates/rsk-fido/src/state.rs",
        "engaged: self.needs_power_cycle",
        "engaged: self.other",
    )
    assert contains(tree.findings(), "the soft lock's field derivation yielded"), tree.findings()


def test_a_guard_may_not_claim_an_operation(tree: Tree):
    """A guard writes no token field, so it implements no A step: tier A carries
    no channel, no retry counter and no clock."""
    tree.replace(
        "assurance/token_refinement.toml",
        'function = "may_walk_rps"\ndisposition = "out-of-scope"',
        'function = "may_walk_rps"\nop = "UseMc"\ndisposition = "out-of-scope"',
    )
    assert contains(tree.findings(), "is out-of-scope and still names an op"), tree.findings()


def test_the_soft_lock_family_scanned_over_the_applet_alone_trips_its_floor(monkeypatch):
    """The measured reason the guard axes scan three units and not one: on the
    real tree `pin_lock` and `restore_pin_lock` have ZERO callers inside
    `rsk-fido`, so the applet-only scan derives 2 sites of 12 and loses the whole
    board half — the marshalling across the warm reset that the clause is about.
    A floor is what turns that into a red row rather than a shorter roster."""
    monkeypatch.setattr(
        token_refinement_gate, "UNITS", ((token_refinement_gate.FIDO, "lib.rs"),)
    )
    findings = token_refinement_gate.audit(token_refinement_gate.ROOT)[0]
    assert contains(findings, "softlock: 2 site(s) derived, under the floor of 8"), findings


@pytest.mark.parametrize(
    "old,new,text",
    [
        ("pub fn pin_lock(", "pub fn lock_state(", "defines no `pin_lock`"),
        ("-> PinLock", "-> &PinLock", "returns no bare type"),
    ],
)
def test_the_soft_locks_anchor_moving_is_a_finding_not_a_traceback(tree: Tree, old, new, text):
    """Both ways `lock_vocabulary`'s anchor can move used to raise, and a
    traceback here aborts all six axes before any of them is compared — so the
    other five would report nothing about a tree nobody had checked."""
    tree.replace("crates/rsk-fido/src/state.rs", old, new)
    assert contains(tree.findings(), text), tree.findings()


def test_a_floor_reports_beside_the_comparison_and_not_instead_of_it(tree: Tree):
    """Measured direction failure: with the window floor at its derived count,
    renaming the guard reported "the derivation stopped reading the tree" and
    SUPPRESSED the accurate `stale owner` line. A row that says the reader broke
    when a security guard was deleted is red for the wrong reason."""
    tree.replace("crates/rsk-fido/src/reset.rs", "RESET_WINDOW_MS", "0")
    findings = token_refinement_gate.audit(tree.root)[0]
    assert contains(findings, "reset_window: 0 site(s) derived, under the floor of"), findings
    assert contains(findings, "reset_window: stale owner"), findings


# --- the keys the file may carry ----------------------------------------------


def test_a_field_nobody_reads_is_refused(tree):
    """Six tables and no list held any of them. Measured before the rule: an
    invented key in the first record left this row at EXIT=0, so a field added
    here was read by nothing and printed by nothing."""
    tree.append(
        "assurance/token_refinement.toml",
        '\n[[walk_owner]]\nfile = "crates/rsk-fido/src/state.rs"\n'
        'function = "may_walk_rps"\nwhy = "x"\ndisposition = "owned"\n'
        'nonsense_field_nobody_holds = "x"\n',
    )
    assert contains(tree.findings(), "which nothing reads")


def test_a_table_nobody_reads_is_refused(tree):
    """And a seventh table, which was invisible in both directions."""
    tree.append(
        "assurance/token_refinement.toml", '\n[[nonsense_table]]\nname = "x"\n'
    )
    assert contains(tree.findings(), "which nothing reads")
