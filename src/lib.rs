//! A Rust port of [bkcrack](https://github.com/kimci86/bkcrack): Biham and
//! Kocher's known-plaintext attack on legacy ZIP encryption (traditional PKWARE
//! encryption, also called ZipCrypto).
//!
//! This is a port, not the original. The attack is from Eli Biham and Paul C.
//! Kocher (FSE 1994); the C++ implementation and documentation this port follows
//! are the work of Joachim Hotonnier. It carries bkcrack's zlib licence.
//!
//! The crate is being built up stage by stage. Available now: the cipher state
//! machine ([`Keys`]), the lookup tables behind it, and the key-recovery attack
//! ([`find_keys`] over [`Data`]). Archive reading and writing and password
//! recovery are not here yet, so the public API is unstable until that work lands.

mod attack;
mod bits;
mod crc32;
mod data;
mod keys;
mod keystream;
mod mult;

pub use attack::{find_keys, ATTACK_SIZE, CONTIGUOUS_SIZE};
pub use data::{Data, DataError, ENCRYPTION_HEADER_SIZE};
pub use keys::Keys;
