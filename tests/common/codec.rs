#![allow(clippy::unwrap_used)]

use sha2::{Digest, Sha256};

use super::*;

fn hex_bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn lz_vector_and_every_prefix() {
    let packed = hex_bytes("00a40170808ff7ec00");
    let output = decompress(&packed, 512, true).unwrap();
    assert_eq!(
        Sha256::digest(&output).as_slice(),
        hex_bytes("4c6474903705cb450bb6434c29e8854f17d8324efca1fdb9ee9008599060883a")
    );
    for size in 0..=packed.len() {
        assert!(
            plausible_prefix(&packed[..size], packed.len(), 512),
            "prefix {size}"
        );
    }
    assert!(decompress(&packed[..packed.len() - 1], 512, true).is_err());
    assert!(decompress(&packed, 511, true).is_err());
    assert!(decompress(&packed, 513, true).is_err());
    let mut padded = packed.clone();
    padded.push(0);
    assert!(decompress(&padded, 512, true).is_err());
    assert_eq!(decompress(&padded, 512, false).unwrap(), output);
    assert!(!plausible_prefix(&[0, 0xe4], 2, 512)); // distance 2 with only one byte of history
}

#[test]
fn filter_uses_independent_ff25_counter_and_wrapping_arithmetic() {
    let mut data = hex_bytes("90e800000000ff2501000000ff2501000000e90100000000000000000000");
    fix_branches(&mut data);
    assert_eq!(&data[2..6], &u32::MAX.to_le_bytes());
    assert_eq!(&data[8..12], &1u32.to_le_bytes());
    assert_eq!(&data[14..18], &5u32.to_le_bytes());
    assert_eq!(&data[19..23], &1u32.wrapping_sub(18).to_le_bytes());
}
