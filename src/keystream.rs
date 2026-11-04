//! The keystream byte produced from the third key word, and the inverse tables
//! that map a keystream byte back to the `Zi[2,16)` values that could produce it.
//!
//! Ported from bkcrack's `KeystreamTab`. The tables need heap allocation, so they
//! are built once on first use.

use crate::bits::{lsb, mask};
use std::sync::LazyLock;

struct KeystreamTab {
    /// Keystream byte indexed by `(z & 0xffff) >> 2`.
    byte: Box<[u8; 1 << 14]>,
    /// For each keystream byte, the `Zi[2,16)` values grouped by `Zi[10,16)`.
    inv_filter: Box<[[Vec<u32>; 64]; 256]>,
    /// For each keystream byte, which `Zi[10,16)` groups are non-empty.
    inv_exists: [u64; 256],
}

static TAB: LazyLock<KeystreamTab> = LazyLock::new(|| {
    let mut byte = Box::new([0u8; 1 << 14]);
    let mut inv_filter: Box<[[Vec<u32>; 64]; 256]> =
        Box::new(std::array::from_fn(|_| std::array::from_fn(|_| Vec::new())));
    let mut inv_exists = [0u64; 256];

    let mut z_2_16: u32 = 0;
    while z_2_16 < (1 << 16) {
        let k = lsb((z_2_16 | 2).wrapping_mul(z_2_16 | 3) >> 8);
        byte[(z_2_16 >> 2) as usize] = k;
        inv_filter[k as usize][(z_2_16 >> 10) as usize].push(z_2_16);
        inv_exists[k as usize] |= 1u64 << (z_2_16 >> 10);
        z_2_16 += 4;
    }

    KeystreamTab {
        byte,
        inv_filter,
        inv_exists,
    }
});

/// The keystream byte for key-word state `z`.
pub(crate) fn get_byte(z: u32) -> u8 {
    TAB.byte[((z & mask(0, 16)) >> 2) as usize]
}

/// The `Zi[2,16)` values consistent with keystream byte `ki` and the given
/// `Zi[10,16)` group.
#[allow(dead_code)] // used by the key-recovery attack (next milestone)
pub(crate) fn get_zi_2_16(ki: u8, zi_10_16: u32) -> &'static [u32] {
    &TAB.inv_filter[ki as usize][((zi_10_16 & mask(0, 16)) >> 10) as usize]
}

/// Whether any `Zi[2,16)` value is consistent with `ki` and the `Zi[10,16)` group.
#[allow(dead_code)] // used by the key-recovery attack (next milestone)
pub(crate) fn has_zi_2_16(ki: u8, zi_10_16: u32) -> bool {
    (TAB.inv_exists[ki as usize] >> ((zi_10_16 & mask(0, 16)) >> 10)) & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_tables_agree_with_forward() {
        // Every Zi[2,16) the inverse table returns for a byte must actually
        // produce that byte, and every group it flags must be non-empty.
        for ki in 0..=255u8 {
            for group in 0..64u32 {
                let zi_10_16 = group << 10;
                let members = get_zi_2_16(ki, zi_10_16);
                assert_eq!(has_zi_2_16(ki, zi_10_16), !members.is_empty());
                for &zi in members {
                    assert_eq!(get_byte(zi), ki);
                    assert_eq!((zi & mask(0, 16)) >> 10, group);
                }
            }
        }
    }

    #[test]
    fn every_z_maps_back_to_itself() {
        // Each z (stepping by 4, the significant resolution) is listed under its
        // own keystream byte.
        let mut z: u32 = 0;
        while z < (1 << 16) {
            let k = get_byte(z);
            assert!(
                get_zi_2_16(k, z).contains(&z),
                "z={z:#x} missing under k={k:#x}"
            );
            z += 4;
        }
    }
}
