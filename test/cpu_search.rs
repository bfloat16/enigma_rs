use super::*;
use crate::{common::crypto, unpack::config::Descriptor};

fn section(index: usize, salt: u32, plain: &[u8]) -> StoredSection {
    let seed = [index as u8 + 17; 16];
    StoredSection {
        descriptor: Descriptor {
            index,
            enabled: true,
            flags: 8,
            packed_size: plain.len(),
            expanded_size: plain.len(),
            rva: 0x1000 * (index as u32 + 1),
            characteristics: 0x40000040,
            seed,
            crc32: crc32fast::hash(plain),
        },
        ciphertext: crypto::decipher(plain, &crypto::section_key(&seed, salt)),
    }
}

#[test]
fn includes_zero_and_uint32_max() {
    for (salt, range) in [
        (0, 0..32),
        (11, 3..12),     // Unaligned four-candidate groups and a scalar tail.
        (4096, 0..4097), // Work allocation boundary.
        (u32::MAX, UINT32_END - 31..UINT32_END),
    ] {
        let sections = [
            section(0, salt, b"abcd"),
            section(1, salt, b"independent section"),
        ];
        assert_eq!(find(&sections, &sections[0], range).unwrap(), Some(salt));
    }
}

#[test]
fn batched_ksa_agrees_with_generic_rc4() {
    for seed in [[0; 16], [255; 16], std::array::from_fn(|i| (i * 13) as u8)] {
        let probe = SectionProbe::new(seed);
        for start in [0, 1, 0x7ffffffe, 0x80000000, 0xfffffffc, 0x17e9532f] {
            for (lane, mut cipher) in probe.ciphers(start).into_iter().enumerate() {
                let salt = start + lane as u32;
                let expected = crypto::decipher(&[0; 1024], &crypto::section_key(&seed, salt));
                let mut actual = [0; 1024];
                cipher.apply(&mut actual);
                assert_eq!(expected, actual);
                probe.cipher(salt).apply(&mut actual);
                assert_eq!(actual, [0; 1024]);
            }
        }
    }
}

#[test]
fn rejects_cross_section_mismatch_and_exhausts_range() {
    let sections = [section(0, 7, b"a"), section(1, 200, b"independent section")];
    assert_eq!(find(&sections, &sections[0], 0..17).unwrap(), None);
}

#[test]
fn explicit_mode_uses_cpu_or_reports_uncompiled_backend() {
    use crate::unpack::search::{Mode, search};
    let sections = [section(0, 11, b"a"), section(1, 11, b"independent section")];
    assert_eq!(search(&sections, Some(Mode::Cpu)).unwrap(), Some(11));
    for (mode, compiled) in [
        (Mode::Cuda, cfg!(all(feature = "cuda", cuda_available))),
        (Mode::Wgpu, cfg!(feature = "wgpu")),
    ] {
        if !compiled {
            let error = search(&sections, Some(mode)).unwrap_err();
            assert!(error.to_string().contains("not enabled in this build"));
        }
    }
}

#[test]
fn compressed_search_continues_past_both_prefix_stages() {
    let mut packed = vec![0x42];
    for i in 0..40u8 {
        packed.push(0);
        packed.extend([i; 8]);
    }
    packed.extend([0xc0, 0]);
    let mut stored = section(0, 12345, &packed);
    stored.descriptor.flags |= 1;
    stored.descriptor.expanded_size = 321;
    let sections = [stored, section(1, 12345, b"independent section")];
    assert_eq!(
        find(&sections, &sections[0], 12300..12429).unwrap(),
        Some(12345)
    );
}
