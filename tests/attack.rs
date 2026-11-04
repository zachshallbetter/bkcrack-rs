//! End-to-end through the public API: build a ZipCrypto stream, recover its
//! internal keys from known plaintext, and check they decrypt the whole stream.
//!
//! This uses enough known plaintext that the search finds the solution quickly.
//! The offset, extra-plaintext and error paths are covered by the crate's unit
//! tests, which drive the attack directly without sweeping every candidate.

use bkcrack::{find_keys, Data, Keys};

const PASSWORD: &str = "correct horse";

fn make_stream(password: &str, header: &[u8; 12], body: &[u8]) -> Vec<u8> {
    let mut keys = Keys::from_password(password);
    let mut stream = Vec::new();
    keys.encrypt(header, &mut stream);
    keys.encrypt(body, &mut stream);
    stream
}

#[test]
fn recovers_keys_and_decrypts_the_stream() {
    let header: [u8; 12] = std::array::from_fn(|i| (i as u8) + 1);
    let body: Vec<u8> = (0..200u32)
        .map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8)
        .collect();
    let stream = make_stream(PASSWORD, &header, &body);

    let data = Data::new(stream.clone(), body.clone(), 0).expect("valid data");
    let solutions = find_keys(&data, false);
    assert_eq!(
        solutions,
        vec![Keys::from_password(PASSWORD)],
        "recovered keys mismatch"
    );

    // The recovered keys decrypt the whole stream back to header + body.
    let mut keys = solutions[0];
    let mut decrypted = Vec::new();
    keys.decrypt(&stream, &mut decrypted);
    assert_eq!(&decrypted[..12], &header);
    assert_eq!(&decrypted[12..], &body[..]);
}

#[test]
fn rejects_data_that_cannot_support_an_attack() {
    let header: [u8; 12] = std::array::from_fn(|i| (i as u8) + 1);
    let body: Vec<u8> = (0..40u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let stream = make_stream(PASSWORD, &header, &body);

    // Ciphertext shorter than the attack minimum.
    assert!(Data::new(stream[..10].to_vec(), body[..8].to_vec(), 0).is_err());
    // Fewer than 8 contiguous bytes.
    assert!(Data::new(stream.clone(), body[..5].to_vec(), 0).is_err());
    // At least 8 contiguous but fewer than 12 known in total.
    assert!(Data::new(stream, body[..10].to_vec(), 0).is_err());
}
