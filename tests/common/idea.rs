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
fn idea_standard_block_vector_and_loader_partial_tail_vectors() {
    let key = hex_bytes("00010002000300040005000600070008")
        .try_into()
        .unwrap();
    let idea = Idea::new(&key);
    let plain = hex_bytes("0000000100020003").try_into().unwrap();
    let cipher = hex_bytes("11fbed2b01986de5").try_into().unwrap();
    assert_eq!(idea.encrypt_block(&plain), cipher);
    assert_eq!(idea.decrypt_block(&cipher), plain);
    // Independent reference values cover the custom short tail and CBC chaining.
    for (n, cipher) in [
        (7, "1bc2f7fe863210"),
        (8, "cd9119c51031fbca"),
        (17, "cd9119c51031fbca5863ebf47cc1a2c82c"),
    ] {
        assert_eq!(
            idea.decrypt(&hex_bytes(cipher)),
            (0..n).collect::<Vec<u8>>()
        );
    }
}
