# bkcrack-rs

A Rust port of [bkcrack](https://github.com/kimci86/bkcrack): Biham and Kocher's
known-plaintext attack on legacy ZIP encryption (traditional PKWARE encryption,
also called ZipCrypto).

This is a port, not the original. The attack, its C++ implementation and the
documentation this README is adapted from are the work of Joachim Hotonnier
(bkcrack). The attack itself is from Eli Biham and Paul C. Kocher,
[A known plaintext attack on the PKZIP stream cipher](https://doi.org/10.1007/3-540-60590-8_12)
(FSE 1994). This port carries bkcrack's zlib licence; see [LICENSE](LICENSE).

## What it does

A ZIP entry encrypted with ZipCrypto is protected by a stream cipher whose entire
state is three 32-bit words. The password initializes those words; after that,
each plaintext byte updates the state and produces one keystream byte, which is
XORed with the data.

The cipher is vulnerable to a known-plaintext attack. Given ciphertext and 12 or
more bytes of the matching plaintext, the three internal keys can be recovered by
working backwards through the update rules. Those keys then decrypt that entry and
**every other entry encrypted with the same password** — the password itself is
never recovered and is not needed. Because the attack works on the cipher state
rather than the password, it is independent of the password's length and
strength: a long random password falls as quickly as a short one once the known
plaintext is available.

The keys can also be used to write a copy of the archive without encryption, or
re-encrypted under a chosen password, or (separately) to search for the original
password, which is only worthwhile if the password string itself is wanted.

## Requirements for the attack

- At least 12 bytes of known plaintext, of which at least 8 are contiguous. More
  known bytes, even at scattered offsets, make the attack faster.
- The known bytes must match the **compressed** stream, because ZipCrypto encrypts
  after Deflate. For a stored (uncompressed) entry this is immediate; for a
  deflated entry it means supplying a file compressed the same way.
- Common sources of known bytes: fixed file-format headers (the PNG signature, a
  JPEG marker, `%PDF-`, an XML declaration), or any file still held in the same
  compressed form.

## Status

Early. This crate is being built up from bkcrack's structure, with each stage
ported faithfully and tested before the next.

- Done: the cipher state machine (`Keys`) and the lookup tables behind it (the
  CRC-32, keystream and multiplication tables), with unit tests and a
  cross-checked keystream vector.
- Next: loading ciphertext and known plaintext, the key-recovery attack
  (candidate generation, reduction and the recursive search), decrypting and
  rewriting archives, and password recovery.

The public API will stabilise once the attack path is complete; until then,
treat it as unstable.

## Usage

```rust
use bkcrack::Keys;

// The three internal keys from a password (for testing and tooling; the attack
// recovers these without the password).
let keys = Keys::from_password("some password");
println!("{:08x} {:08x} {:08x}", keys.x(), keys.y(), keys.z());
```

## Credits

- Eli Biham and Paul C. Kocher — the attack (FSE 1994).
- Joachim Hotonnier — [bkcrack](https://github.com/kimci86/bkcrack), the C++
  implementation and documentation this port follows.
