//! A Rust port of [bkcrack](https://github.com/kimci86/bkcrack): Biham and
//! Kocher's known-plaintext attack on legacy ZIP encryption (traditional PKWARE
//! encryption, also called ZipCrypto).
//!
//! This is a port, not the original. The attack is from Eli Biham and Paul C.
//! Kocher (FSE 1994); the C++ implementation and documentation this port follows
//! are the work of Joachim Hotonnier. It carries bkcrack's zlib licence.
//!
//! The crate is being built up stage by stage. Available now: the cipher state
//! machine ([`Keys`]) and the lookup tables behind it. The key-recovery attack,
//! archive I/O and password recovery are not here yet, so the public API is
//! unstable until that work lands.

mod bits;
mod crc32;
mod keys;
mod keystream;
mod mult;

pub use keys::Keys;
