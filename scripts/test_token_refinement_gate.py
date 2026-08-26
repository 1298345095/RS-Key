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

LIB = """pub mod state;
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
        return token_refinement_gate.audit(self.root)[0]


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
    assert token_refinement_gate.main() == 0
    assert capsys.readouterr().out.startswith("token-refinement-gate: GREEN")


def test_main_reports_every_finding_and_exits_nonzero(tree: Tree, monkeypatch, capsys):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.in_use = true; }\n")
    monkeypatch.setattr(token_refinement_gate, "ROOT", tree.root)
    assert token_refinement_gate.main() == 1
    assert "unowned concrete site" in capsys.readouterr().err
