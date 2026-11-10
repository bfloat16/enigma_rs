#![allow(clippy::unwrap_used)]

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
fn section_key_and_rc4_vector() {
    let seed = hex_bytes("0d961f3742a264754b33b15078ac40e4")
        .try_into()
        .unwrap();
    let key = section_key(&seed, 0x17e9532f);
    assert_eq!(&key[16..], hex_bytes("9e8bd381a281e4fd0c934dc36fb738e6"));
    let cipher = hex_bytes("5596b7f6448a8aebd6");
    let plain = decipher(&cipher, &key);
    assert_eq!(plain, hex_bytes("00a40170808ff7ec00"));
    assert_eq!(crc32fast::hash(&plain), 0x23c734e7);
    assert_ne!(crc32fast::hash(&decipher(&cipher, &seed)), 0x23c734e7);
}
