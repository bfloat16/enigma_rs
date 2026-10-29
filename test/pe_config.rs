use enigma_rs::{
    common::{crypto, pe::Pe},
    unpack::config,
};

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

fn literal_stream(plain: &[u8]) -> Vec<u8> {
    struct Writer {
        bytes: Vec<u8>,
        tag: usize,
        count: u8,
    }
    impl Writer {
        fn bit(&mut self, bit: bool) {
            if self.count == 0 {
                self.tag = self.bytes.len();
                self.bytes.push(0);
            }
            if bit {
                self.bytes[self.tag] |= 0x80 >> self.count;
            }
            self.count = (self.count + 1) & 7;
        }
    }
    let mut out = Writer {
        bytes: vec![plain[0]],
        tag: 0,
        count: 0,
    };
    for &byte in &plain[1..] {
        out.bit(false);
        out.bytes.push(byte);
    }
    for bit in [true, true, false] {
        out.bit(bit);
    }
    out.bytes.push(0);
    out.bytes
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

#[test]
fn bootstrap_patch_restores_ciphertext_before_section_verification() {
    use enigma_rs::unpack::extract::{self, Recovered};
    let mut bytes = fixture(false);
    let plain = (0u8..32).collect::<Vec<_>>();
    let seed = [0x5a; 16];
    let cipher = crypto::decipher(&plain, &seed);
    bytes[0x10400..0x10420].copy_from_slice(&cipher);
    bytes[0x10407..0x1040c].fill(0xcc);
    let pe = Pe::parse(&bytes).unwrap();
    let mut config = config::Configuration {
        descriptors: vec![config::Descriptor {
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
    assert!(extract::verify_all(&extract::stored_sections(&pe, &config).unwrap(), None).is_err());
    config.entry_patch = Some(Recovered {
        rva: 0x20007,
        bytes: cipher[7..12].to_vec(),
    });
    let sections = extract::stored_sections(&pe, &config).unwrap();
    assert_eq!(extract::decode(&sections[0], None, false).unwrap(), plain);
    assert_eq!(&bytes[0x10407..0x1040c], &[0xcc; 5]);
    config.entry_patch.as_mut().unwrap().rva = 0x2001e;
    assert!(extract::stored_sections(&pe, &config).is_err());
}

#[test]
fn both_architectures_decode_reached_metadata_arguments_and_verify_hashes() {
    for is_64 in [false, true] {
        let mut bytes = fixture(is_64);
        let key = md5::compute(&bytes[0x10400..0x10800]).0;
        let mut plain = vec![0; 116];
        put(&mut plain, 24, 1); // one descriptor after the zero-length patch
        plain[28] = 1;
        put(&mut plain, 28 + 12, 16);
        put(&mut plain, 28 + 16, 0x20000);
        put(&mut plain, 28 + 36, 0x40000040);
        plain.push(1); // unrecognized fixed config is retained without inventing a ctx layout
        let digest = md5::compute(&plain[16..]).0;
        plain[..16].copy_from_slice(&digest);
        let stream = literal_stream(&plain);
        let cipher = crypto::decipher(&stream, &key);
        let rva = 0x20240;
        let mut arguments = if is_64 {
            vec![
                0x48, 0x81, 0xc4, 0x20, 0, 0, 0, 0x49, 0x89, 0xe1, 0x49, 0xc7, 0xc0, 0, 0, 0, 0,
                0x48, 0x89, 0xea,
            ]
        } else {
            vec![0x54, 0x64, 0xff, 0x35, 0, 0, 0, 0, 0x68, 0, 0, 0, 0]
        };
        put(&mut arguments, if is_64 { 13 } else { 9 }, rva);
        arguments.push(0xc3);
        bytes[0x10800..0x10a00].fill(0);
        // A plausible argument sequence in skipped junk must never win over
        // the reached call setup. The false metadata has no valid digest.
        let mut junk = arguments.clone();
        put(&mut junk, if is_64 { 13 } else { 9 }, rva + 0x20);
        bytes[0x10800..0x10802].copy_from_slice(&[0xeb, 0x1e]);
        bytes[0x10802..0x10802 + junk.len()].copy_from_slice(&junk);
        bytes[0x10820..0x10820 + arguments.len()].copy_from_slice(&arguments);
        let at = 0x10840;
        put(&mut bytes, at, 1);
        put(&mut bytes, at + 4, cipher.len() as u32);
        put(&mut bytes, at + 8, plain.len() as u32);
        bytes[at + 12..at + 28].copy_from_slice(&md5::compute(&cipher).0);
        bytes[at + 28..at + 28 + cipher.len()].copy_from_slice(&cipher);
        let pe = Pe::parse(&bytes).unwrap();
        let decoded = config::parse(&pe).unwrap();
        assert!(decoded.ctx.is_none());
        assert_eq!(decoded.descriptors[0].rva, 0x20000);
        assert_eq!(decoded.descriptors[0].characteristics, 0x40000040);
        bytes[at + 28] ^= 1;
        assert!(config::parse(&Pe::parse(&bytes).unwrap()).is_err());
    }
}
