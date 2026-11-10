#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn key() -> [u8; 16] {
    bytes("00010002000300040005000600070008")
        .try_into()
        .unwrap()
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
    let imports = parse_records(&data, &key(), 1, false).unwrap();
    assert_eq!(imports.len(), 3);
    assert_eq!(imports[0].dll, "KERNEL32.dll");
    assert_eq!(imports[0].name.as_deref(), Some("ExitProcess"));
    assert_eq!(imports[1].iat_rva, 0x1004);
    assert_eq!(imports[2].ordinal, Some(9));
    assert!(parse_records(&data[..data.len() - 3], &key(), 1, false).is_err());
    let mut trailing = data.clone();
    trailing.push(0);
    assert!(parse_records(&trailing, &key(), 1, false).is_err());
    assert!(parse_records(&data, &[0; 16], 1, false).is_err());
    let mut duplicate = data;
    let size = duplicate.len();
    duplicate[size - 5..size - 1].copy_from_slice(&0x1000u32.to_le_bytes());
    assert!(parse_records(&duplicate, &key(), 1, false).is_err());
}

#[test]
fn real_dword_flags_include_high_bits_and_a_dword_terminator() {
    let data = bytes(
        "010000000c00a2b2903e9835fed6df89d0ff860000000d00e3006d9125ded6344de132bbe6010000000000ac002c00ffffffff",
    );
    let key = bytes("ab24d57d12c1cc2d4d1e2f685d6a6dee")
        .try_into()
        .unwrap();
    let imports = parse_records(&data, &key, 4, false).unwrap();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].dll.to_ascii_lowercase(), "kernel32.dll");
    assert_eq!(imports[0].iat_rva, 0x2c00ac);
    assert!(parse_records(&data, &key, 1, false).is_err());
}

#[test]
fn x64_ordinals_are_qwords_but_references_remain_rvas() {
    let mut data = vec![1, 12, 0];
    data.extend(bytes("baf09a5a7cb5d92d8f7f41fd"));
    data.push(0);
    let ordinal_at = data.len();
    data.extend(0x8000000000000158u64.to_le_bytes());
    data.extend(1u16.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    data.extend(0x363088u32.to_le_bytes());
    data.push(255);
    let result = parse_records(&data, &key(), 1, true).unwrap();
    assert_eq!(result[0].ordinal, Some(0x158));
    assert_eq!(result[0].iat_rva, 0x363088);
    assert!(parse_records(&data, &key(), 1, false).is_err());
    data[ordinal_at + 4] = 1;
    assert!(parse_records(&data, &key(), 1, true).is_err());
}
