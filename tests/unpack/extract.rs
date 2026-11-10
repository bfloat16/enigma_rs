#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn put(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn fixture() -> Vec<u8> {
    let mut data = vec![0; 0x10a00];
    data[..2].copy_from_slice(b"MZ");
    put(&mut data, 0x3c, 0x10000);
    let nt = 0x10000;
    data[nt..nt + 4].copy_from_slice(b"PE\0\0");
    data[nt + 4..nt + 6].copy_from_slice(&0x14cu16.to_le_bytes());
    data[nt + 6..nt + 8].copy_from_slice(&2u16.to_le_bytes());
    data[nt + 20..nt + 22].copy_from_slice(&224u16.to_le_bytes());
    let opt = nt + 24;
    data[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    put(&mut data, opt + 16, 0x20200);
    put(&mut data, opt + 28, 0x400000);
    put(&mut data, opt + 32, 0x200);
    put(&mut data, opt + 36, 0x200);
    put(&mut data, opt + 56, 0x30000);
    put(&mut data, opt + 60, 0x10400);
    put(&mut data, opt + 92, 16);
    let table = opt + 224;
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
fn bootstrap_patch_restores_ciphertext_before_section_verification() {
    let mut bytes = fixture();
    let plain = (0u8..32).collect::<Vec<_>>();
    let seed = [0x5a; 16];
    let cipher = crypto::decipher(&plain, &seed);
    bytes[0x10400..0x10420].copy_from_slice(&cipher);
    bytes[0x10407..0x1040c].fill(0xcc);
    let pe = Pe::parse(&bytes).unwrap();
    let mut config = Configuration {
        descriptors: vec![Descriptor {
            index: 0,
            enabled: true,
            flags: 8,
            packed_size: 32,
            expanded_size: 32,
            rva: 0x20000,
            characteristics: 0x60000020,
            seed,
            crc32: crc32fast::hash(&plain),
        }],
        entry_patch: None,
        ctx: None,
        loader: None,
        layout: None,
    };
    assert!(verify_all(&stored_sections(&pe, &config).unwrap(), None).is_err());
    config.entry_patch = Some(Recovered {
        rva: 0x20007,
        bytes: cipher[7..12].to_vec(),
    });
    let sections = stored_sections(&pe, &config).unwrap();
    assert_eq!(decode(&sections[0], None, false).unwrap(), plain);
    assert_eq!(&bytes[0x10407..0x1040c], &[0xcc; 5]);
    config.entry_patch.as_mut().unwrap().rva = 0x2001e;
    assert!(stored_sections(&pe, &config).is_err());
}
