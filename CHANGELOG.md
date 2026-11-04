# Changelog

All notable changes to this crate are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [Unreleased]

### Added

- The cipher state machine (`Keys`): forward and backward updates, encrypt and
  decrypt.
- The key-recovery attack: `find_keys` over `Data`, with candidate generation and
  reduction (`Zreduction`) and the recursive Z/Y/X search (`Attack`), run across
  all cores, and scattered extra plaintext supported.
- The lookup tables behind it: the CRC-32 forward and inverse steps, the
  keystream byte with its inverse filter tables, and the multiplication fibers.
- Tests: the table inverses, a keystream known-answer vector cross-checked
  against a separate implementation of the documented schedule, and encrypt /
  decrypt and forward / backward round-trips.

Archive reading and writing and password recovery are not implemented yet. The
public API is unstable until that work lands.
