//! CRC-32 steps and their inverses, as used by the ZipCrypto key schedule.
//!
//! Ported from bkcrack's `Crc32Tab`. The forward and inverse per-byte tables are
//! built at compile time from the reflected CRC-32 polynomial.

use crate::bits::{lsb, mask, msb};

const POLYNOMIAL: u32 = 0xedb88320;

const fn build_tables() -> ([u32; 256], [u32; 256]) {
    let mut forward = [0u32; 256];
    let mut inverse = [0u32; 256];
    let mut b = 0usize;
    while b < 256 {
        let mut crc = b as u32;
        let mut i = 0;
        while i < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            i += 1;
        }
        forward[b] = crc;
        inverse[msb(crc) as usize] = (crc << 8) ^ b as u32;
        b += 1;
    }
    (forward, inverse)
}

const TABLES: ([u32; 256], [u32; 256]) = build_tables();
const FORWARD: [u32; 256] = TABLES.0;
const INVERSE: [u32; 256] = TABLES.1;

/// One CRC-32 update: fold plaintext byte `b` into state `pval`.
pub(crate) const fn crc32(pval: u32, b: u8) -> u32 {
    (pval >> 8) ^ FORWARD[(lsb(pval) ^ b) as usize]
}

/// The inverse of [`crc32`]: `crc32inv(crc32(x, b), b) == x`.
pub(crate) const fn crc32inv(crc: u32, b: u8) -> u32 {
    (crc << 8) ^ INVERSE[msb(crc) as usize] ^ b as u32
}

/// `Yi[24,32)` given `Zi` and `Zi-1`, from the key-update relations.
#[allow(dead_code)] // used by the key-recovery attack (next milestone)
pub(crate) const fn get_yi_24_32(zi: u32, zim1: u32) -> u32 {
    (crc32inv(zi, 0) ^ zim1) << 24
}

/// `Zi-1[10,32)` given `Zi[2,32)` (the low 10 bits are discarded).
#[allow(dead_code)] // used by the key-recovery attack (next milestone)
pub(crate) const fn get_zim1_10_32(zi_2_32: u32) -> u32 {
    crc32inv(zi_2_32, 0) & mask(10, 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_and_inverse_round_trip() {
        for state in [0u32, 1, 0x12345678, 0xffff_ffff, 0xdead_beef] {
            for b in 0..=255u8 {
                assert_eq!(crc32inv(crc32(state, b), b), state, "state={state:#x} b={b}");
            }
        }
    }

    #[test]
    fn matches_standard_crc32_table() {
        // The forward table is the standard reflected CRC-32 table: entry 0 is 0,
        // and entry 0xff is 0x2d02ef8d (a well-known fixed value).
        assert_eq!(FORWARD[0], 0x0000_0000);
        assert_eq!(FORWARD[0xff], 0x2d02_ef8d);
    }

    #[test]
    fn get_zim1_discards_low_ten_bits() {
        assert_eq!(get_zim1_10_32(0xffff_ffff) & 0x3ff, 0);
    }
}
