//! The ZipCrypto cipher state: the three 32-bit key words, their forward and
//! backward updates, and the keystream byte.
//!
//! Ported from bkcrack's `Keys`.

use crate::bits::{lsb, msb};
use crate::crc32::{crc32, crc32inv};
use crate::keystream;
use crate::mult::{MULT, MULT_INV};

/// The internal state of the ZipCrypto keystream generator: three 32-bit words.
///
/// The password sets the initial state; the attack recovers it directly, without
/// the password. From the state, any entry encrypted with the same password can
/// be decrypted.
///
/// ```
/// use bkcrack::Keys;
///
/// let mut keys = Keys::from_password("my password");
/// let mut ciphertext = Vec::new();
/// keys.encrypt(b"secret", &mut ciphertext);
///
/// let mut plaintext = Vec::new();
/// Keys::from_password("my password").decrypt(&ciphertext, &mut plaintext);
/// assert_eq!(plaintext, b"secret");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Keys {
    x: u32,
    y: u32,
    z: u32,
}

impl Default for Keys {
    /// The constant initial state before any password byte is mixed in.
    fn default() -> Self {
        Keys {
            x: 0x12345678,
            y: 0x23456789,
            z: 0x34567890,
        }
    }
}

impl Keys {
    /// Keys from their three words (for example, recovered by the attack).
    pub fn new(x: u32, y: u32, z: u32) -> Self {
        Keys { x, y, z }
    }

    /// Keys initialized from a password.
    pub fn from_password(password: &str) -> Self {
        Self::from_bytes(password.as_bytes())
    }

    /// Keys initialized from raw password bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut keys = Keys::default();
        for &p in bytes {
            keys.update(p);
        }
        keys
    }

    /// The first key word.
    pub fn x(&self) -> u32 {
        self.x
    }

    /// The second key word.
    pub fn y(&self) -> u32 {
        self.y
    }

    /// The third key word.
    pub fn z(&self) -> u32 {
        self.z
    }

    /// The keystream byte for the current state.
    pub fn key_byte(&self) -> u8 {
        keystream::get_byte(self.z)
    }

    /// Advance the state by one plaintext byte.
    pub fn update(&mut self, p: u8) {
        self.x = crc32(self.x, p);
        self.y = self
            .y
            .wrapping_add(lsb(self.x) as u32)
            .wrapping_mul(MULT)
            .wrapping_add(1);
        self.z = crc32(self.z, msb(self.y));
    }

    /// Step the state back by one byte, given the ciphertext byte `c`.
    pub fn update_backward(&mut self, c: u8) {
        self.z = crc32inv(self.z, msb(self.y));
        self.y = self
            .y
            .wrapping_sub(1)
            .wrapping_mul(MULT_INV)
            .wrapping_sub(lsb(self.x) as u32);
        // After z is reverted, the keystream byte is the one used at this step.
        let p = c ^ keystream::get_byte(self.z);
        self.x = crc32inv(self.x, p);
    }

    /// Step the state back by one byte, given the plaintext byte `p` directly.
    pub fn update_backward_plaintext(&mut self, p: u8) {
        self.z = crc32inv(self.z, msb(self.y));
        self.y = self
            .y
            .wrapping_sub(1)
            .wrapping_mul(MULT_INV)
            .wrapping_sub(lsb(self.x) as u32);
        self.x = crc32inv(self.x, p);
    }

    /// Encrypt `plaintext`, appending the ciphertext to `out` and advancing the
    /// state.
    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut Vec<u8>) {
        out.reserve(plaintext.len());
        for &p in plaintext {
            out.push(p ^ self.key_byte());
            self.update(p);
        }
    }

    /// Decrypt `ciphertext`, appending the plaintext to `out` and advancing the
    /// state.
    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) {
        out.reserve(ciphertext.len());
        for &c in ciphertext {
            let p = c ^ self.key_byte();
            self.update(p);
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_the_initial_state() {
        let k = Keys::default();
        assert_eq!((k.x(), k.y(), k.z()), (0x12345678, 0x23456789, 0x34567890));
        assert_eq!(Keys::from_bytes(&[]), Keys::default());
    }

    #[test]
    fn matches_an_independent_keystream_vector() {
        // Cross-checked against a separate implementation of the documented
        // PKWARE key schedule (see the port's test notes): password "bkcrack-rs".
        let keys = Keys::from_password("bkcrack-rs");
        assert_eq!(
            (keys.x(), keys.y(), keys.z()),
            (0x2e2acfbf, 0x1662008b, 0xd15b530c)
        );

        let expected: [u8; 16] = [
            0x67, 0xe6, 0x2c, 0xf3, 0x6e, 0xcd, 0xbb, 0x6f, 0x87, 0x1a, 0x46, 0xee, 0xa0, 0xf6,
            0x7e, 0x32,
        ];
        // Encrypting zero bytes yields the keystream itself.
        let mut ks = keys;
        let mut out = Vec::new();
        ks.encrypt(&[0u8; 16], &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        for password in ["", "a", "correct horse", "a-longer-passphrase-123!"] {
            let plaintext = b"The quick brown fox jumps over the lazy dog. 0123456789";
            let mut ciphertext = Vec::new();
            Keys::from_password(password).encrypt(plaintext, &mut ciphertext);
            assert_ne!(&ciphertext, plaintext, "password={password:?}");

            let mut recovered = Vec::new();
            Keys::from_password(password).decrypt(&ciphertext, &mut recovered);
            assert_eq!(&recovered, plaintext, "password={password:?}");
        }
    }

    #[test]
    fn backward_inverts_forward() {
        let start = Keys::from_password("seed");
        let plaintext = b"abcdefgh";

        // update_backward_plaintext undoes update, in reverse order.
        let mut k = start;
        for &p in plaintext {
            k.update(p);
        }
        for &p in plaintext.iter().rev() {
            k.update_backward_plaintext(p);
        }
        assert_eq!(k, start);

        // update_backward undoes update given the ciphertext it produced.
        let mut k = start;
        let mut cipher = Vec::new();
        k.encrypt(plaintext, &mut cipher);
        for &c in cipher.iter().rev() {
            k.update_backward(c);
        }
        assert_eq!(k, start);
    }
}
