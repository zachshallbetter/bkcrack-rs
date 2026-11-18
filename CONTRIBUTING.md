# Contributing to bkcrack-rs

`bkcrack-rs` is a Rust port of [bkcrack](https://github.com/kimci86/bkcrack), the known-plaintext attack on legacy ZIP encryption. The port follows bkcrack's structure, with each stage ported faithfully and tested before the next. The [README](README.md) lists what is done and what is next.

## Setup

You need a stable Rust toolchain (minimum supported version 1.80) with `rustfmt` and `clippy`, and Python 3 for the index check.

```sh
git clone https://github.com/zachshallbetter/bkcrack-rs.git
cd bkcrack-rs
cargo build
```

## Checks

CI runs these (`.github/workflows/ci.yml`). Run them before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
python3 tools/reflect.py --check
```

If you change the public API or a module's purpose line, run `python3 tools/reflect.py` and commit the regenerated `docs/reflection.md`.

## Conventions

- **Faithful port.** Behavior matches the original bkcrack: candidate counts and recovered keys are checked against it. Explain any deliberate difference in the pull request.
- **Tests with each stage.** New behavior comes with a test, such as a known-answer vector or a round trip.
- **No `unsafe`.** The crate sets `unsafe_code = "forbid"`. Public items need docs (`missing_docs` is a warning, and clippy runs with `-D warnings`).
- **Licence and credit.** The crate carries bkcrack's zlib licence. Keep the credits to Biham and Kocher and to Joachim Hotonnier intact.
- **Commits.** Short imperative subjects, with a conventional prefix where it fits (`ci:`, `docs:`).
- **Changelog.** Note changes under `## [Unreleased]` in `CHANGELOG.md`.

## Pull requests

Describe what changed and why, list the checks you ran, and keep the diff to one concern. Use the pull request template.

Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.
