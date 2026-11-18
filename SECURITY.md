# Security Policy

## Reporting a vulnerability

Report security issues privately through GitHub private vulnerability reporting:
<https://github.com/zachshallbetter/bkcrack-rs/security/advisories/new>.
Do not open a public issue for a vulnerability.

Include a description of the issue and its impact, steps to reproduce (a minimal example is ideal), and the affected version or commit.

This is a solo-maintained project. Handling is best-effort with no SLA: there is no guaranteed acknowledgement or fix time, and the maintainer will respond when next active.

## Scope

`bkcrack-rs` is a Rust library implementing a known-plaintext attack on legacy ZIP encryption (ZipCrypto). That the attack works is the point of the library and is not a vulnerability. It is intended for archives you own or are authorized to access. In scope:

- Memory-safety or panic bugs in the library on crafted input (the crate forbids `unsafe` code), and unbounded resource use in `Data` construction or the attack.
- Results that are wrong: recovered keys or decrypted output that do not match the ZipCrypto definition.
- Supply-chain concerns in the repository's CI configuration or dependencies.

Reports about the weakness of ZipCrypto itself, or requests to attack archives you do not control, are out of scope.

## Supported versions

The crate is pre-release (`0.0.1`). Only `main` receives fixes.
