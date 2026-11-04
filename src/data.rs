//! The data for an attack: ciphertext, known plaintext, the derived keystream,
//! and any scattered extra plaintext, with the offsets lined up.
//!
//! Ported from bkcrack's `Data`. Where bkcrack merges plaintext in place, this
//! chooses the longest contiguous run of known bytes directly, which has the
//! same result and is simpler to follow.

use crate::attack::{ATTACK_SIZE, CONTIGUOUS_SIZE};
use std::collections::BTreeMap;
use std::fmt;

/// Size of the traditional PKWARE encryption header that precedes the data.
pub const ENCRYPTION_HEADER_SIZE: usize = 12;

/// The reason a set of ciphertext and plaintext cannot be used for an attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataError(String);

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "data error: {}", self.0)
    }
}

impl std::error::Error for DataError {}

/// The inputs to the attack, validated and aligned.
#[derive(Clone, Debug)]
pub struct Data {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) plaintext: Vec<u8>,
    pub(crate) keystream: Vec<u8>,
    pub(crate) offset: usize,
    pub(crate) extra_plaintext: Vec<(usize, u8)>,
}

impl Data {
    /// Build attack data from ciphertext (including the 12-byte encryption
    /// header) and a contiguous run of known plaintext.
    ///
    /// `offset` is where the plaintext sits relative to the ciphertext *after*
    /// the header, so it may be negative (down to `-12`) when the known
    /// plaintext covers part of the header.
    pub fn new(ciphertext: Vec<u8>, plaintext: Vec<u8>, offset: i32) -> Result<Self, DataError> {
        Self::with_extra(ciphertext, plaintext, offset, None, &BTreeMap::new())
    }

    /// As [`Data::new`], with an optional check byte (the last header byte, at
    /// offset `-1`) and scattered extra known bytes at their own offsets
    /// relative to the ciphertext after the header.
    pub fn with_extra(
        ciphertext: Vec<u8>,
        plaintext: Vec<u8>,
        offset: i32,
        check_byte: Option<u8>,
        extra: &BTreeMap<i32, u8>,
    ) -> Result<Self, DataError> {
        let hdr = ENCRYPTION_HEADER_SIZE;
        let min_offset = -(hdr as i32);

        if ciphertext.len() < ATTACK_SIZE {
            return Err(DataError(format!(
                "ciphertext is too small for an attack (minimum length is {ATTACK_SIZE})"
            )));
        }
        if ciphertext.len() < plaintext.len() {
            return Err(DataError("ciphertext is smaller than plaintext".into()));
        }
        if offset < min_offset {
            return Err(DataError(format!(
                "plaintext offset {offset} is too small (minimum is {min_offset})"
            )));
        }
        let base = usize::try_from(hdr as i32 + offset).expect("offset >= -12");
        if ciphertext.len() < base + plaintext.len() {
            return Err(DataError(format!("plaintext offset {offset} is too large")));
        }
        if let Some((&first_k, _)) = extra.iter().next() {
            if first_k < min_offset {
                return Err(DataError(format!(
                    "extra plaintext offset {first_k} is too small (minimum is {min_offset})"
                )));
            }
        }
        if let Some((&last_k, _)) = extra.iter().next_back() {
            if ciphertext.len() <= usize::try_from(hdr as i32 + last_k).unwrap_or(usize::MAX) {
                return Err(DataError(format!(
                    "extra plaintext offset {last_k} is too large"
                )));
            }
        }

        // All known bytes as absolute ciphertext position -> byte. Extra
        // overrides the provided plaintext; the check byte fills position 11 only
        // when nothing else already does.
        let mut known: BTreeMap<usize, u8> = BTreeMap::new();
        for (i, &b) in plaintext.iter().enumerate() {
            known.insert(base + i, b);
        }
        for (&k, &b) in extra {
            known.insert(usize::try_from(hdr as i32 + k).expect("checked above"), b);
        }
        if let Some(cb) = check_byte {
            known.entry(hdr - 1).or_insert(cb);
        }

        // The longest contiguous run of known positions becomes the plaintext.
        let (run_start, run_len) = longest_run(&known);
        let new_plaintext: Vec<u8> = (run_start..run_start + run_len)
            .map(|p| known[&p])
            .collect();

        if new_plaintext.len() < CONTIGUOUS_SIZE {
            return Err(DataError(format!(
                "not enough contiguous plaintext ({} bytes available, minimum is {CONTIGUOUS_SIZE})",
                new_plaintext.len()
            )));
        }
        if known.len() < ATTACK_SIZE {
            return Err(DataError(format!(
                "not enough plaintext ({} bytes available, minimum is {ATTACK_SIZE})",
                known.len()
            )));
        }

        // Everything outside the run is scattered extra plaintext, ordered for
        // the attack: positions below the run descending, then positions above
        // it ascending.
        let run_end = run_start + run_len;
        let mut extra_plaintext: Vec<(usize, u8)> =
            known.range(..run_start).map(|(&p, &b)| (p, b)).collect();
        extra_plaintext.reverse();
        extra_plaintext.extend(known.range(run_end..).map(|(&p, &b)| (p, b)));

        let keystream: Vec<u8> = new_plaintext
            .iter()
            .enumerate()
            .map(|(i, &p)| p ^ ciphertext[run_start + i])
            .collect();

        Ok(Data {
            ciphertext,
            plaintext: new_plaintext,
            keystream,
            offset: run_start,
            extra_plaintext,
        })
    }

    /// The derived keystream bytes (plaintext XOR ciphertext over the run).
    pub fn keystream(&self) -> &[u8] {
        &self.keystream
    }
}

/// `(start, length)` of the longest run of consecutive keys in `known`.
fn longest_run(known: &BTreeMap<usize, u8>) -> (usize, usize) {
    let mut best = (0usize, 0usize);
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;
    let mut prev: Option<usize> = None;
    for &pos in known.keys() {
        if prev == Some(pos.wrapping_sub(1)) {
            cur_len += 1;
        } else {
            cur_start = pos;
            cur_len = 1;
        }
        if cur_len > best.1 {
            best = (cur_start, cur_len);
        }
        prev = Some(pos);
    }
    best
}
