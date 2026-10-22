# Issue #136 — section alignment gate and bounded evidence (2026-10-22)

## Scope and provenance

Upstream issue: https://github.com/TheMaxMur/RS-Key/issues/136 .
The October 20 report documents an **unmodified upstream default** firmware
build at `960b20a89809f87d96568f62c29bbe78b9ac8104` with Rust 1.99.1,
a linker diagnostic, no flashed board, and **unknown runtime impact**. That
report did **not** include a complete Rust 1.96.0 firmware build.

A separate later **custom-profile fork** workflow succeeded:
https://github.com/1298345095/RS-Key/actions/runs/39463088811 .
Commit `03c9ec94efa82cac3875b2d28132ebb146d0d9d0`,
Rust 1.96.0, YubiKey5, RP2350-Zero-CM, 2 MB flash, 896K KVMAIN;
artifact `12283394897` (`RS-Key-YubiKey5-RP2350-Zero-CM`)
contains ELF and UF2. In an October 22 *read-only inspection*, the artifact
ZIP SHA-256 was verified against GitHub's digest:
`36feb69f7b853b80f9bcdc6dafbdad5771f56d4d35529a8c9ffd1ec2a58906b8`.
Direct ELF-header parsing and GNU `readelf -SW` agreed:
`.text` section address `0x1000013c`, declared alignment `8`,
`0x1000013c % 8 = 4`.

This establishes that the discrepancy also appears in an older-toolchain
**custom** firmware ELF. It is **not** a controlled same-configuration
Rust 1.96.0 vs Rust 1.99.1 experiment and **not** default-profile
acceptance evidence. It says nothing conclusive about runtime failure.
The evidence above was supplied from a prior inspection; this patch does not
claim to have repeated the ZIP download or independently authenticated its digest.

## Gate changes

`scripts/elf_gate.py` now adds `readelf -SW` to its existing binary reads.
Its check verifies that the reported section count and indexed rows parse,
rejects missing/unparseable section data, and checks non-NULL section virtual
addresses against the declared power-of-two `sh_addralign`. Absent `.text`,
duplicate sections, invalid alignments, or malformed rows are findings.
The historical program-header fixture is preserved. The regression reproduces
the **observed** `.text` address/alignment as a negative case. All ordinary
legacy mutation tests use a separately named **SYNTHETIC ALIGNED CONTROL**
(`0x10000140` substituted into section-header text only). This synthetic
fixture is not a built ELF and is not evidence of a successful linker fix.

The registry remains default-profile-only (`assurance/image.toml`); no
flash/KVMAIN/YubiKey settings, linker script, firmware code, image registry,
or acceptance profile were changed. A future *default-profile* build should
run this gate at its existing position, against that exact ELF, and separately
assess whether the linker layout should be changed.

## Validation environment and limits

Recorded commands and actual output in the available local inspection shell:

```console
$ python --version
Python 3.13.5
$ python -m pytest --version
pytest 9.0.2
$ readelf --version | head -n 1
GNU readelf (GNU Binutils for Debian) 2.44
$ command -v rustc || echo 'rustc not found'
rustc not found
$ command -v cargo || echo 'cargo not found'
cargo not found
$ command -v nix || echo 'nix not found'
nix not found
$ command -v arm-none-eabi-readelf || echo 'arm-none-eabi-readelf not found'
arm-none-eabi-readelf not found
```

**Test execution limitation:** the shell cannot resolve github.com for a
checkout, and the connected GitHub file API cannot materialize a working tree
in that shell. Consequently `python -m pytest scripts/test_elf_gate.py -q`
has **not** been executed against this branch here. Do not describe these tests
as passing until a real checkout/CI run supplies its exit code and output.
Suggested verification in a checkout:

```sh
python -m pytest scripts/test_elf_gate.py -q
python -m pytest scripts -q
```

The firmware was **not rebuilt** with an alignment fix. No hardware was
flashed or boot-tested. A gate failure is diagnostic validation, not a claim
that a linker change is correct, harmless, or ready for production.
