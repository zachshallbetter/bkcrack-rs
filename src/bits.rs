//! Small bit helpers shared by the lookup tables and the cipher.
//!
//! Ported from bkcrack's `types.hpp` (`lsb`, `msb`, `mask`).

/// The least significant byte of `x`.
pub(crate) const fn lsb(x: u32) -> u8 {
    x as u8
}

/// The most significant byte of `x`.
pub(crate) const fn msb(x: u32) -> u8 {
    (x >> 24) as u8
}

/// A mask with bits `[begin, end)` set. `begin` is in `0..32`, `end` in `1..=32`.
pub(crate) const fn mask(begin: u32, end: u32) -> u32 {
    (u32::MAX << begin) & (u32::MAX >> (32 - end))
}

/// The largest difference the attack tolerates when comparing `x`-bit fields:
/// `mask(0, x) + 0xff`.
pub(crate) const fn maxdiff(x: u32) -> u32 {
    mask(0, x).wrapping_add(0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(lsb(0xdeadbeef), 0xef);
        assert_eq!(msb(0xdeadbeef), 0xde);
    }

    #[test]
    fn masks() {
        assert_eq!(mask(0, 32), 0xffff_ffff);
        assert_eq!(mask(0, 16), 0x0000_ffff);
        assert_eq!(mask(10, 32), 0xffff_fc00);
        assert_eq!(mask(24, 32), 0xff00_0000);
    }
}
