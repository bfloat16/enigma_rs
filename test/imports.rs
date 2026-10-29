use enigma_rs::{common::idea::Idea, unpack::imports};

use super::bytes;

fn key() -> [u8; 16] {
    bytes("00010002000300040005000600070008")
        .try_into()
        .unwrap()
}

#[test]
fn idea_standard_block_vector_and_loader_partial_tail_vectors() {
    let idea = Idea::new(&key());
    let plain = bytes("0000000100020003").try_into().unwrap();
    let cipher = bytes("11fbed2b01986de5").try_into().unwrap();
    assert_eq!(idea.encrypt_block(&plain), cipher);
    assert_eq!(idea.decrypt_block(&cipher), plain);
    // Independent reference values cover the custom short tail and CBC chaining.
    for (n, cipher) in [
        (7, "1bc2f7fe863210"),
        (8, "cd9119c51031fbca"),
        (17, "cd9119c51031fbca5863ebf47cc1a2c82c"),
    ] {
        assert_eq!(idea.decrypt(&bytes(cipher)), (0..n).collect::<Vec<u8>>());
    }
}

fn stream() -> Vec<u8> {
    let mut data = vec![1, 12, 0];
    data.extend(bytes("baf09a5a7cb5d92d8f7f41fd"));
    data.extend([0x16, 11, 0]);
    data.extend(bytes("45fb8ffd0a6941de02362e"));
    data.extend(2u16.to_le_bytes());
    for rva in [0x1000u32, 0x1004] {
        data.extend(0u32.to_le_bytes());
        data.extend(rva.to_le_bytes());
    }
    data.push(0);
    data.extend(0x80000009u32.to_le_bytes());
    data.extend(1u16.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    data.extend(0x1008u32.to_le_bytes());
    data.push(255);
    data
}

#[test]
fn parse_named_ordinal_and_multiple_references_without_name_nuls() {
    let data = stream();
    let imports = imports::parse_records(&data, &key(), 1).unwrap();
    assert_eq!(imports.len(), 3);
    assert_eq!(imports[0].dll, "KERNEL32.dll");
    assert_eq!(imports[0].name.as_deref(), Some("ExitProcess"));
    assert_eq!(imports[1].iat_rva, 0x1004);
    assert_eq!(imports[2].ordinal, Some(9));
    assert!(imports::parse_records(&data[..data.len() - 3], &key(), 1).is_err());
    let mut trailing = data.clone();
    trailing.push(0);
    assert!(imports::parse_records(&trailing, &key(), 1).is_err());
    assert!(imports::parse_records(&data, &[0; 16], 1).is_err());
    let mut duplicate = data;
    let size = duplicate.len();
    duplicate[size - 5..size - 1].copy_from_slice(&0x1000u32.to_le_bytes());
    assert!(imports::parse_records(&duplicate, &key(), 1).is_err());
}

#[test]
fn real_dword_flags_include_high_bits_and_a_dword_terminator() {
    let data = bytes(
        "010000000c00a2b2903e9835fed6df89d0ff860000000d00e3006d9125ded6344de132bbe6010000000000ac002c00ffffffff",
    );
    let key = bytes("ab24d57d12c1cc2d4d1e2f685d6a6dee")
        .try_into()
        .unwrap();
    let imports = imports::parse_records(&data, &key, 4).unwrap();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].dll.to_ascii_lowercase(), "kernel32.dll");
    assert_eq!(imports[0].iat_rva, 0x2c00ac);
    assert!(imports::parse_records(&data, &key, 1).is_err());
}
