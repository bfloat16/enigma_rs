#![allow(clippy::unwrap_used)]

use super::*;

fn put(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn fixture(is_64: bool) -> Vec<u8> {
    // A high e_lfanew catches the C uint16 truncation; oversized .text raw data
    // overlaps the next RVA, which must map to that next section instead.
    let mut data = vec![0; 0x10a00];
    data[..2].copy_from_slice(b"MZ");
    put(&mut data, 0x3c, 0x10000);
    let nt = 0x10000;
    data[nt..nt + 4].copy_from_slice(b"PE\0\0");
    data[nt + 4..nt + 6].copy_from_slice(&(if is_64 { 0x8664u16 } else { 0x14c }).to_le_bytes());
    data[nt + 6..nt + 8].copy_from_slice(&2u16.to_le_bytes());
    let size = if is_64 { 240u16 } else { 224 };
    data[nt + 20..nt + 22].copy_from_slice(&size.to_le_bytes());
    let opt = nt + 24;
    data[opt..opt + 2].copy_from_slice(&(if is_64 { 0x20bu16 } else { 0x10b }).to_le_bytes());
    put(&mut data, opt + 16, 0x20200);
    if is_64 {
        data[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    } else {
        put(&mut data, opt + 28, 0x400000);
    }
    put(&mut data, opt + 32, 0x200);
    put(&mut data, opt + 36, 0x200);
    put(&mut data, opt + 56, 0x30000);
    put(&mut data, opt + 60, 0x10400);
    put(&mut data, opt + if is_64 { 108 } else { 92 }, 16);
    let table = opt + size as usize;
    for (index, rva, raw, raw_size, name) in [
        (0, 0x20000, 0x10400, 0x400, b".text"),
        (1, 0x20200, 0x10800, 0x200, b".pack"),
    ] {
        let at = table + index * 40;
        data[at..at + 5].copy_from_slice(name);
        put(&mut data, at + 8, 0x200);
        put(&mut data, at + 12, rva);
        put(&mut data, at + 16, raw_size);
        put(&mut data, at + 20, raw);
    }
    data[0x10400..0x10800].fill(0xaa);
    data[0x10800..].fill(0xbb);
    data
}

#[test]
fn pe32_and_pe64_use_full_lfanew_and_correct_overlapping_rva_mapping() {
    for is_64 in [false, true] {
        let bytes = fixture(is_64);
        let pe = Pe::parse(&bytes).unwrap();
        assert_eq!(pe.read(0x20200, 2).unwrap(), [0xbb; 2]);
        assert!(pe.read(0x201ff, 2).is_err());
    }
}

#[test]
fn empty_sections_do_not_conflict_with_or_shadow_mapped_sections() {
    for is_64 in [false, true] {
        let mut bytes = fixture(is_64);
        let nt = 0x10000;
        bytes[nt + 6..nt + 8].copy_from_slice(&3u16.to_le_bytes());
        let table = nt + 24 + if is_64 { 240 } else { 224 };
        let empty = table + 80;
        for rva in [0x20200, 0x20100] {
            put(&mut bytes, empty + 12, rva);
            let pe = Pe::parse(&bytes).unwrap();
            assert_eq!(pe.sections.len(), 3);
            assert_eq!(pe.read(0x20200, 2).unwrap(), [0xbb; 2]);
            assert_eq!(pe.read(0x200ff, 2).unwrap(), [0xaa; 2]);
        }
        put(&mut bytes, empty + 12, 0x20200);
        put(&mut bytes, empty + 8, 1);
        assert!(Pe::parse(&bytes).is_err());
    }
}
