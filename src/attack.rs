//! The key-recovery attack: given known keystream (and any scattered extra
//! plaintext), search for the ZipCrypto internal keys.
//!
//! Ported from bkcrack's `Attack` and its `attack` driver, together with
//! `Zreduction`. The search is the recursive exploration of the Z, Y and X
//! lists, with the recovered keys verified against the full known plaintext.

use crate::bits::{lsb, mask, maxdiff, msb};
use crate::crc32::{crc32, crc32inv, get_yi_24_32, get_zim1_10_32};
use crate::data::Data;
use crate::keys::Keys;
use crate::keystream::{get_zi_2_16, has_zi_2_16};
use crate::mult::{msbprod_fiber2, msbprod_fiber3, MULT_INV};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Contiguous known plaintext bytes the attack needs.
pub const CONTIGUOUS_SIZE: usize = 8;
/// Total known plaintext bytes the attack needs.
pub const ATTACK_SIZE: usize = 12;

/// Recover the ZipCrypto internal keys from `data`.
///
/// With `exhaustive` false, the search stops at the first solution (ZipCrypto
/// recovery is effectively unique, so this is the usual choice). With it true,
/// every candidate is tried and all solutions are returned.
pub fn find_keys(data: &Data, exhaustive: bool) -> Vec<Keys> {
    let mut zr = Zreduction::new(&data.keystream);
    if data.keystream.len() > CONTIGUOUS_SIZE {
        zr.reduce();
    }
    zr.generate();

    let index = zr.index();
    let candidates = zr.candidates();
    if candidates.is_empty() {
        return Vec::new();
    }

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(candidates.len())
        .max(1);
    let next = AtomicUsize::new(0);
    let found = AtomicBool::new(false);
    let solutions = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut attack = Attack::new(data, index);
                loop {
                    if !exhaustive && found.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= candidates.len() {
                        break;
                    }
                    attack.carryout(candidates[i]);
                    if !attack.solutions.is_empty() {
                        solutions
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .append(&mut attack.solutions);
                        if !exhaustive {
                            found.store(true, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });

    solutions.into_inner().unwrap_or_else(|e| e.into_inner())
}

struct Attack<'a> {
    data: &'a Data,
    /// Starting index of the used plaintext and keystream window.
    index: usize,
    solutions: Vec<Keys>,
    zlist: [u32; CONTIGUOUS_SIZE],
    ylist: [u32; CONTIGUOUS_SIZE],
    xlist: [u32; CONTIGUOUS_SIZE],
}

impl<'a> Attack<'a> {
    fn new(data: &'a Data, index: usize) -> Self {
        Attack {
            data,
            index: index + 1 - CONTIGUOUS_SIZE,
            solutions: Vec::new(),
            zlist: [0; CONTIGUOUS_SIZE],
            ylist: [0; CONTIGUOUS_SIZE],
            xlist: [0; CONTIGUOUS_SIZE],
        }
    }

    fn carryout(&mut self, z7_2_32: u32) {
        self.zlist[7] = z7_2_32;
        self.explore_zlists(7);
    }

    fn explore_zlists(&mut self, i: usize) {
        if i != 0 {
            // Generate Z{i-1}[2,32) values.
            let zim1_10_32 = get_zim1_10_32(self.zlist[i]);
            let ks = self.data.keystream[self.index + i - 1];
            for &zim1_2_16 in get_zi_2_16(ks, zim1_10_32) {
                self.zlist[i - 1] = zim1_10_32 | zim1_2_16;
                self.zlist[i] &= mask(2, 32);
                self.zlist[i] |= (crc32inv(self.zlist[i], 0) ^ self.zlist[i - 1]) >> 8;
                if i < 7 {
                    self.ylist[i + 1] = get_yi_24_32(self.zlist[i + 1], self.zlist[i]);
                }
                self.explore_zlists(i - 1);
            }
        } else {
            // The Z-list is complete; iterate over possible Y values.
            let mut prod =
                (MULT_INV.wrapping_mul(u32::from(msb(self.ylist[7]))) << 24).wrapping_sub(MULT_INV);
            let mut y7_8_24: u32 = 0;
            while y7_8_24 < (1 << 24) {
                let target = msb(self.ylist[6]).wrapping_sub(msb(prod));
                for &y7_0_8 in msbprod_fiber3(target) {
                    if prod
                        .wrapping_add(MULT_INV.wrapping_mul(u32::from(y7_0_8)))
                        .wrapping_sub(self.ylist[6] & mask(24, 32))
                        <= maxdiff(24)
                    {
                        self.ylist[7] =
                            u32::from(y7_0_8) | y7_8_24 | (self.ylist[7] & mask(24, 32));
                        self.explore_ylists(7);
                    }
                }
                y7_8_24 += 1 << 8;
                prod = prod.wrapping_add(MULT_INV << 8);
            }
        }
    }

    fn explore_ylists(&mut self, i: usize) {
        if i != 3 {
            // Generate Y{i-1} values.
            let fy = self.ylist[i].wrapping_sub(1).wrapping_mul(MULT_INV);
            let ffy = fy.wrapping_sub(1).wrapping_mul(MULT_INV);
            let target = msb(ffy.wrapping_sub(self.ylist[i - 2] & mask(24, 32)));
            for &xi_0_8 in msbprod_fiber2(target) {
                let yim1 = fy.wrapping_sub(u32::from(xi_0_8));
                if ffy
                    .wrapping_sub(MULT_INV.wrapping_mul(u32::from(xi_0_8)))
                    .wrapping_sub(self.ylist[i - 2] & mask(24, 32))
                    <= maxdiff(24)
                    && msb(yim1) == msb(self.ylist[i - 1])
                {
                    self.ylist[i - 1] = yim1;
                    self.xlist[i] = u32::from(xi_0_8);
                    self.explore_ylists(i - 1);
                }
            }
        } else {
            self.test_xlist();
        }
    }

    fn test_xlist(&mut self) {
        for i in 5..=7 {
            self.xlist[i] = (crc32(self.xlist[i - 1], self.data.plaintext[self.index + i - 1])
                & mask(8, 32))
                | u32::from(lsb(self.xlist[i]));
        }

        let mut x = self.xlist[7];
        for i in (3..=6).rev() {
            x = crc32inv(x, self.data.plaintext[self.index + i]);
        }

        let y1_26_32 = get_yi_24_32(self.zlist[1], self.zlist[0]) & mask(26, 32);
        if self.ylist[3]
            .wrapping_sub(1)
            .wrapping_mul(MULT_INV)
            .wrapping_sub(u32::from(lsb(x)))
            .wrapping_sub(1)
            .wrapping_mul(MULT_INV)
            .wrapping_sub(y1_26_32)
            > maxdiff(26)
        {
            return;
        }

        let offset = self.data.offset;
        let plaintext = &self.data.plaintext;
        let ciphertext = &self.data.ciphertext;

        // Verify forward from index + 7 to the end of the known plaintext.
        let mut keys_forward = Keys::new(self.xlist[7], self.ylist[7], self.zlist[7]);
        keys_forward.update(plaintext[self.index + 7]);
        {
            let mut p = self.index + 8;
            let mut c = offset + self.index + 8;
            while p < plaintext.len() {
                if (ciphertext[c] ^ keys_forward.key_byte()) != plaintext[p] {
                    return;
                }
                keys_forward.update(plaintext[p]);
                p += 1;
                c += 1;
            }
        }
        let mut index_forward = offset + plaintext.len();

        // Verify backward from index + 3 down to the start of the known plaintext.
        let mut keys_backward = Keys::new(x, self.ylist[3], self.zlist[3]);
        {
            let mut k = self.index + 3;
            while k > 0 {
                k -= 1;
                let c = ciphertext[offset + k];
                keys_backward.update_backward(c);
                if (c ^ keys_backward.key_byte()) != plaintext[k] {
                    return;
                }
            }
        }
        let mut index_backward = offset;

        // Check the scattered extra plaintext (backward entries first, then
        // forward entries, by the ordering Data established).
        for &(extra_index, extra_byte) in &self.data.extra_plaintext {
            let p = if extra_index < index_backward {
                for &c in ciphertext[extra_index..index_backward].iter().rev() {
                    keys_backward.update_backward(c);
                }
                index_backward = extra_index;
                ciphertext[index_backward] ^ keys_backward.key_byte()
            } else {
                for &c in &ciphertext[index_forward..extra_index] {
                    let pb = c ^ keys_forward.key_byte();
                    keys_forward.update(pb);
                }
                index_forward = extra_index;
                ciphertext[index_forward] ^ keys_forward.key_byte()
            };
            if p != extra_byte {
                return;
            }
        }

        // Roll the keys back to the very start of the ciphertext stream.
        for &c in ciphertext[0..index_backward].iter().rev() {
            keys_backward.update_backward(c);
        }

        self.solutions.push(keys_backward);
    }
}

/// Generate and reduce the Z-value candidates the attack iterates over.
///
/// Ported from bkcrack's `Zreduction`.
struct Zreduction<'a> {
    keystream: &'a [u8],
    zi_vector: Vec<u32>,
    index: usize,
}

impl<'a> Zreduction<'a> {
    fn new(keystream: &'a [u8]) -> Self {
        let index = keystream.len() - 1;
        let ki = keystream[index];
        let mut zi_vector = Vec::new();
        for shifted in 0u32..(1 << 22) {
            if has_zi_2_16(ki, shifted << 10) {
                zi_vector.push(shifted << 10);
            }
        }
        Zreduction {
            keystream,
            zi_vector,
            index,
        }
    }

    fn reduce(&mut self) {
        const TRACK_SIZE_THRESHOLD: usize = 1 << 16;
        const WAIT_SIZE_THRESHOLD: usize = 1 << 8;

        let mut tracking = false;
        let mut best_copy: Vec<u32> = Vec::new();
        let mut best_index = self.index;
        let mut best_size = TRACK_SIZE_THRESHOLD;
        let mut waiting = false;
        let mut wait: usize = 0;

        let mut zim1_vector: Vec<u32> = Vec::new();
        // 2^22 bits, cleared each step.
        let mut seen = vec![0u64; 1 << 16];

        let mut i = self.index;
        while i >= CONTIGUOUS_SIZE {
            zim1_vector.clear();
            seen.iter_mut().for_each(|w| *w = 0);
            let mut number_of_zim1_2_32: usize = 0;
            let ki = self.keystream[i];
            let kim1 = self.keystream[i - 1];

            for &zi_10_32 in &self.zi_vector {
                for &zi_2_16 in get_zi_2_16(ki, zi_10_32) {
                    let zim1_10_32 = get_zim1_10_32(zi_10_32 | zi_2_16);
                    let bit = (zim1_10_32 >> 10) as usize;
                    let m = 1u64 << (bit & 63);
                    if seen[bit >> 6] & m == 0 && has_zi_2_16(kim1, zim1_10_32) {
                        zim1_vector.push(zim1_10_32);
                        seen[bit >> 6] |= m;
                        number_of_zim1_2_32 += get_zi_2_16(kim1, zim1_10_32).len();
                    }
                }
            }

            if number_of_zim1_2_32 <= best_size {
                tracking = true;
                best_index = i - 1;
                best_size = number_of_zim1_2_32;
                waiting = false;
            } else if tracking {
                if best_index == i {
                    std::mem::swap(&mut best_copy, &mut self.zi_vector);
                    if best_size <= WAIT_SIZE_THRESHOLD {
                        waiting = true;
                        wait = best_size * 4;
                    }
                }
                if waiting {
                    wait = wait.wrapping_sub(1);
                    if wait == 0 {
                        break;
                    }
                }
            }

            std::mem::swap(&mut self.zi_vector, &mut zim1_vector);
            if i == CONTIGUOUS_SIZE {
                break;
            }
            i -= 1;
        }

        if tracking {
            if best_index != CONTIGUOUS_SIZE - 1 {
                std::mem::swap(&mut self.zi_vector, &mut best_copy);
            }
            self.index = best_index;
        } else {
            self.index = CONTIGUOUS_SIZE - 1;
        }
    }

    fn generate(&mut self) {
        let ki = self.keystream[self.index];
        let n = self.zi_vector.len();
        for idx in 0..n {
            let base = self.zi_vector[idx];
            let candidates = get_zi_2_16(ki, base);
            if let Some((&first, rest)) = candidates.split_first() {
                for &zi_2_16 in rest {
                    self.zi_vector.push(base | zi_2_16);
                }
                self.zi_vector[idx] = base | first;
            }
        }
    }

    fn candidates(&self) -> &[u32] {
        &self.zi_vector
    }

    fn index(&self) -> usize {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Data;
    use crate::keys::Keys;
    use std::collections::BTreeMap;

    fn make_stream(pw: &str, header: &[u8; 12], body: &[u8]) -> Vec<u8> {
        let mut k = Keys::from_password(pw);
        let mut s = Vec::new();
        k.encrypt(header, &mut s);
        k.encrypt(body, &mut s);
        s
    }

    fn header() -> [u8; 12] {
        std::array::from_fn(|i| (i as u8) + 1)
    }

    fn body(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
            .collect()
    }

    // Reduce to candidates, confirm the true one survived, then drive the attack
    // with just that candidate (one carryout) — fast and independent of how many
    // candidates there are. `full_plain` is the stream's plaintext (header + body).
    fn carryout_true(pw: &str, full_plain: &[u8], data: &Data) -> Vec<Keys> {
        let mut zr = Zreduction::new(&data.keystream);
        if data.keystream.len() > CONTIGUOUS_SIZE {
            zr.reduce();
        }
        zr.generate();
        let index = zr.index();

        // The cipher state at a ciphertext position evolves on the plaintext up to
        // that position; the candidate sits at position offset + index.
        let pos = data.offset + index;
        let mut k = Keys::from_password(pw);
        let mut sink = Vec::new();
        k.encrypt(&full_plain[0..pos], &mut sink);
        let true_z = k.z() & mask(2, 32);
        assert!(
            zr.candidates().contains(&true_z),
            "reduction dropped the true candidate"
        );

        let mut attack = Attack::new(data, index);
        attack.carryout(true_z);
        attack.solutions
    }

    fn full_plain(header: &[u8; 12], body: &[u8]) -> Vec<u8> {
        let mut v = header.to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn recovers_from_contiguous_plaintext() {
        let pw = "correct horse";
        let (h, b) = (header(), body(40));
        let stream = make_stream(pw, &h, &b);
        let data = Data::new(stream.clone(), b.clone(), 0).unwrap();
        assert_eq!(
            carryout_true(pw, &full_plain(&h, &b), &data),
            vec![Keys::from_password(pw)]
        );
    }

    #[test]
    fn recovers_with_a_plaintext_offset() {
        let pw = "correct horse";
        let (h, b) = (header(), body(48));
        let stream = make_stream(pw, &h, &b);
        let data = Data::new(stream.clone(), b[5..25].to_vec(), 5).unwrap();
        assert_eq!(
            carryout_true(pw, &full_plain(&h, &b), &data),
            vec![Keys::from_password(pw)]
        );
    }

    #[test]
    fn recovers_with_a_long_password() {
        let pw = "a-much-longer-passphrase-with-symbols-!@#-2026";
        let (h, b) = (header(), body(48));
        let stream = make_stream(pw, &h, &b);
        let data = Data::new(stream.clone(), b.clone(), 0).unwrap();
        assert_eq!(
            carryout_true(pw, &full_plain(&h, &b), &data),
            vec![Keys::from_password(pw)]
        );
    }

    #[test]
    fn accepts_correct_extra_plaintext() {
        let pw = "correct horse";
        let (h, b) = (header(), body(48));
        let stream = make_stream(pw, &h, &b);
        let mut extra = BTreeMap::new();
        extra.insert(20i32, b[20]);
        extra.insert(31i32, b[31]);
        let data = Data::with_extra(stream.clone(), b[..14].to_vec(), 0, None, &extra).unwrap();
        assert_eq!(
            carryout_true(pw, &full_plain(&h, &b), &data),
            vec![Keys::from_password(pw)]
        );
    }

    #[test]
    fn rejects_wrong_extra_plaintext() {
        let pw = "correct horse";
        let (h, b) = (header(), body(48));
        let stream = make_stream(pw, &h, &b);
        let mut extra = BTreeMap::new();
        extra.insert(20i32, b[20] ^ 0xff);
        let data = Data::with_extra(stream.clone(), b[..14].to_vec(), 0, None, &extra).unwrap();
        assert!(
            carryout_true(pw, &full_plain(&h, &b), &data).is_empty(),
            "wrong extra must rule out the keys"
        );
    }
}
