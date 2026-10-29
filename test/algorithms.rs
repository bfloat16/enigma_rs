use enigma_rs::common::{codec, crypto};
use sha2::{Digest, Sha256};

use super::bytes;

#[test]
fn section_key_and_rc4_vector() {
    let seed = bytes("0d961f3742a264754b33b15078ac40e4")
        .try_into()
        .unwrap();
    let key = crypto::section_key(&seed, 0x17e9532f);
    assert_eq!(&key[16..], bytes("9e8bd381a281e4fd0c934dc36fb738e6"));
    let cipher = bytes("5596b7f6448a8aebd6");
    let plain = crypto::decipher(&cipher, &key);
    assert_eq!(plain, bytes("00a40170808ff7ec00"));
    assert_eq!(crc32fast::hash(&plain), 0x23c734e7);
    assert_ne!(
        crc32fast::hash(&crypto::decipher(&cipher, &seed)),
        0x23c734e7
    );
}

#[test]
fn lz_vector_and_every_prefix() {
    let packed = bytes("00a40170808ff7ec00");
    let output = codec::decompress(&packed, 512, true).unwrap();
    assert_eq!(
        Sha256::digest(&output).as_slice(),
        bytes("4c6474903705cb450bb6434c29e8854f17d8324efca1fdb9ee9008599060883a")
    );
    for size in 0..=packed.len() {
        assert!(
            codec::plausible_prefix(&packed[..size], packed.len(), 512),
            "prefix {size}"
        );
    }
    assert!(codec::decompress(&packed[..packed.len() - 1], 512, true).is_err());
    assert!(codec::decompress(&packed, 511, true).is_err());
    assert!(codec::decompress(&packed, 513, true).is_err());
    let mut padded = packed.clone();
    padded.push(0);
    assert!(codec::decompress(&padded, 512, true).is_err());
    assert_eq!(codec::decompress(&padded, 512, false).unwrap(), output);
    assert!(!codec::plausible_prefix(&[0, 0xe4], 2, 512)); // distance 2 with only one byte of history
}

#[test]
fn filter_uses_independent_ff25_counter_and_wrapping_arithmetic() {
    let mut data = bytes("90e800000000ff2501000000ff2501000000e90100000000000000000000");
    codec::fix_branches(&mut data);
    assert_eq!(&data[2..6], &u32::MAX.to_le_bytes());
    assert_eq!(&data[8..12], &1u32.to_le_bytes());
    assert_eq!(&data[14..18], &5u32.to_le_bytes());
    assert_eq!(&data[19..23], &1u32.wrapping_sub(18).to_le_bytes());
}
