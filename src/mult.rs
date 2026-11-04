//! The multiplication constant from the key schedule, its inverse, and the
//! "fiber" tables that invert the `y` update during the attack.
//!
//! Ported from bkcrack's `MultTab`.

use crate::bits::msb;
use std::sync::LazyLock;

/// The constant `y` is multiplied by in the forward key update.
pub(crate) const MULT: u32 = 0x08088405;
/// Its multiplicative inverse modulo 2^32.
pub(crate) const MULT_INV: u32 = 0xd94fa8cd;

const _: () = assert!(MULT.wrapping_mul(MULT_INV) == 1);

struct MultTab {
    fiber2: [Vec<u8>; 256],
    #[allow(dead_code)] // used by the key-recovery attack (next milestone)
    fiber3: [Vec<u8>; 256],
}

static TAB: LazyLock<MultTab> = LazyLock::new(|| {
    let mut fiber2: [Vec<u8>; 256] = std::array::from_fn(|_| Vec::new());
    let mut fiber3: [Vec<u8>; 256] = std::array::from_fn(|_| Vec::new());

    let mut prodinv: u32 = 0; // x * MULT_INV
    for x in 0..256u32 {
        let m = msb(prodinv) as usize;
        fiber2[m].push(x as u8);
        fiber2[(m + 1) % 256].push(x as u8);
        fiber3[(m + 255) % 256].push(x as u8);
        fiber3[m].push(x as u8);
        fiber3[(m + 1) % 256].push(x as u8);
        prodinv = prodinv.wrapping_add(MULT_INV);
    }

    MultTab { fiber2, fiber3 }
});

/// Candidate `x` values whose `msb(x * MULT_INV)` is `msbprodinv` or one less.
#[allow(dead_code)] // used by the key-recovery attack (next milestone)
pub(crate) fn msbprod_fiber2(msbprodinv: u8) -> &'static [u8] {
    &TAB.fiber2[msbprodinv as usize]
}

/// The wider fiber used one step deeper in the attack.
#[allow(dead_code)] // used by the key-recovery attack (next milestone)
pub(crate) fn msbprod_fiber3(msbprodinv: u8) -> &'static [u8] {
    &TAB.fiber3[msbprodinv as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_is_correct() {
        assert_eq!(MULT.wrapping_mul(MULT_INV), 1);
    }

    #[test]
    fn fiber2_contains_every_x_under_its_two_targets() {
        for x in 0..256u32 {
            let m = msb(x.wrapping_mul(MULT_INV));
            assert!(msbprod_fiber2(m).contains(&(x as u8)), "x={x} missing under msb");
            assert!(msbprod_fiber2(m.wrapping_add(1)).contains(&(x as u8)), "x={x} under msb+1");
        }
    }

    #[test]
    fn fibers_only_hold_valid_members() {
        for target in 0..=255u8 {
            for &x in msbprod_fiber2(target) {
                let m = msb((x as u32).wrapping_mul(MULT_INV));
                assert!(m == target || m.wrapping_add(1) == target);
            }
        }
    }
}
