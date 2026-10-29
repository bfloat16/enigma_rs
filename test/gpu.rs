use cubecl::Runtime;
#[cfg(feature = "wgpu")]
use enigma_rs::unpack::wgpu_search;
use enigma_rs::{
    common::{codec, crypto},
    unpack::{config::Descriptor, extract::StoredSection, gpu_kernel, search},
};

fn section(salt: u32, packed: &[u8], expected: usize, compressed: bool) -> StoredSection {
    let seed = std::array::from_fn(|i| (i * 13 + 71) as u8);
    StoredSection {
        descriptor: Descriptor {
            index: 0,
            enabled: true,
            flags: 8 | u32::from(compressed),
            packed_size: packed.len(),
            expanded_size: expected,
            rva: 0x1000,
            characteristics: 0x40000040,
            seed,
            crc32: crc32fast::hash(packed),
        },
        ciphertext: crypto::decipher(packed, &crypto::section_key(&seed, salt)),
    }
}

fn cpu_hits(section: &StoredSection, start: u64, end: u64) -> Vec<u32> {
    (start..end)
        .filter_map(|value| {
            let plain = crypto::decipher(
                &section.ciphertext,
                &crypto::section_key(&section.descriptor.seed, value as u32),
            );
            (crc32fast::hash(&plain) == section.descriptor.crc32
                && (section.descriptor.flags & 1 == 0
                    || codec::plausible_prefix(
                        &plain[..plain.len().min(64)],
                        plain.len(),
                        section.descriptor.expanded_size,
                    )))
            .then_some(value as u32)
        })
        .collect()
}

fn matches_independent_cpu<R: Runtime>(
    create_probe: fn(&StoredSection) -> anyhow::Result<gpu_kernel::GpuProbe<R>>,
) {
    let packed = [0x00, 0xa4, 0x01, 0x70, 0x80, 0x8f, 0xf7, 0xec, 0x00];
    for (salt, start, end) in [
        (0, 0, 131),
        (130, 0, 131),
        (0x80000000, 0x7fffffc0, 0x80000041),
        (u32::MAX, 0xffffff7f, search::UINT32_END),
    ] {
        for compressed in [false, true] {
            let stored = section(
                salt,
                &packed,
                if compressed { 512 } else { packed.len() },
                compressed,
            );
            let mut probe = create_probe(&stored).unwrap();
            assert_eq!(
                probe.scan(start, end).unwrap(),
                cpu_hits(&stored, start, end)
            );
        }
    }
    // Exercise PRGA wraparound and CRC beyond the 64-byte prefix.
    let plain: Vec<u8> = (0..1041).map(|i| (i * 73 + 3) as u8).collect();
    let stored = section(12345, &plain, plain.len(), false);
    let mut probe = create_probe(&stored).unwrap();
    assert_eq!(
        probe.scan(12300, 12429).unwrap(),
        cpu_hits(&stored, 12300, 12429)
    );
    // A valid literal stream crosses both prefix stages and the RC4 index wrap.
    let mut packed = vec![0x42];
    for i in 0..40u8 {
        packed.push(0); // Eight literal tokens.
        packed.extend([i; 8]);
    }
    packed.extend([0xc0, 0]); // LZ terminator.
    assert_eq!(codec::decompress(&packed, 321, true).unwrap().len(), 321);
    let stored = section(12345, &packed, 321, true);
    let mut probe = create_probe(&stored).unwrap();
    assert_eq!(probe.scan(12300, 12429).unwrap(), vec![12345]);

    // A one-byte CRC admits many keys. Check atomic append, sorting, and counter
    // reset when reusing the same candidate buffer for a different interval.
    let stored = section(123, &[0x42], 1, false);
    let mut probe = create_probe(&stored).unwrap();
    for (start, end) in [(0, 8193), (8193, 16384), (0, 1)] {
        assert_eq!(
            probe.scan(start, end).unwrap(),
            cpu_hits(&stored, start, end)
        );
    }
    // Force a CRC hit at a known salt to compare conservative prefix rejection,
    // including exhaustion, invalid distances, oversized gamma codes and tails.
    for (plain, expected) in [
        (vec![0, 0xe4], 512),
        (vec![0xff; 64], 512),
        (vec![0xff; 3], 512),
    ] {
        let stored = section(123, &plain, expected, true);
        let mut probe = create_probe(&stored).unwrap();
        assert_eq!(probe.scan(123, 124).unwrap(), cpu_hits(&stored, 123, 124));
    }
}

#[test]
#[cfg(feature = "wgpu")]
#[ignore = "requires a discrete GPU and WGPU driver; run with --ignored --nocapture"]
fn wgpu_matches_independent_cpu_at_boundaries() {
    matches_independent_cpu(wgpu_search::probe);
}

#[test]
#[cfg(all(feature = "cuda", cuda_available))]
#[ignore = "requires NVIDIA GPU, CUDA NVRTC and headers; run with --ignored --nocapture"]
fn cuda_matches_independent_cpu_at_boundaries() {
    if let Some(status) = enigma_rs::unpack::cuda_search::runtime_relaunch().unwrap() {
        assert!(status.success());
        return;
    }
    matches_independent_cpu(enigma_rs::unpack::cuda_search::probe);
}

#[test]
#[ignore = "exercises GPU selection and CPU fallback; run with --ignored --nocapture"]
fn search_checks_all_sections() {
    #[cfg(all(feature = "cuda", cuda_available))]
    if let Some(status) = enigma_rs::unpack::cuda_search::runtime_relaunch().unwrap() {
        assert!(status.success());
        return;
    }
    // The one-byte screen admits many wrong keys before the correct salt.
    let sections = [
        section(12345, &[0x42], 1, false),
        section(12345, b"independent section", 19, false),
    ];
    for mode in [
        None,
        Some(search::Mode::Cpu),
        #[cfg(all(feature = "cuda", cuda_available))]
        Some(search::Mode::Cuda),
        #[cfg(feature = "wgpu")]
        Some(search::Mode::Wgpu),
    ] {
        assert_eq!(search::search(&sections, mode).unwrap(), Some(12345));
    }
}
