use super::*;
use sha2::{Digest, Sha256};

const STATES: &[u8; 512] = include_bytes!("fixtures/evb_states.bin");

#[test]
fn encrypted_v1_records_are_interleaved_with_file_data() {
    let states = include_bytes!("fixtures/evb_v1_states.bin");
    let container = include_bytes!("fixtures/evb_v1_container.bin");
    let metadata = states[..256].try_into().unwrap();
    let header = decipher(&container[56..120], metadata);
    assert_eq!(u32_at(&header, 20).unwrap(), 1);
    assert_eq!(u64_at(&header, 48).unwrap(), container.len() as u64);
    let files = interleaved_directory(container, metadata).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, PathBuf::from("GCR.key"));
    assert_eq!(files[0].size, 16);
    assert_eq!(files[0].offset, 301);
    assert!(interleaved_directory(&container[..container.len() - 1], metadata).is_err());

    // v1 changes directory placement, not the per-file compression/index format.
    let content: &[u8; 256] = states[256..512].try_into().unwrap();
    let plain = vec![b'A'; 128];
    for compressed in [false, true] {
        let stored = if compressed {
            let block = literals(&plain);
            let mut index = 12u64.to_le_bytes().to_vec();
            index.extend((block.len() as u32).to_le_bytes());
            let mut stored = decipher(&index, content);
            stored.extend(decipher(&block, content));
            stored
        } else {
            decipher(&plain, content)
        };
        let mut record = vec![0; 12];
        for word in "payload.bin".encode_utf16().chain([0]) {
            record.extend(word.to_le_bytes());
        }
        record.extend([2, 0, 0]); // File kind, flags, policy.
        record.extend((plain.len() as u64).to_le_bytes());
        record.extend([0; 31]); // Dates/attributes and empty alternate name.
        record.extend((stored.len() as u64).to_le_bytes());
        let mut data = vec![0; 120];
        data.extend(decipher(&(record.len() as u32).to_le_bytes(), metadata));
        data.extend(decipher(&record, metadata));
        data.extend(stored);
        let nodes = interleaved_directory(&data, metadata).unwrap();
        let decoded = stored_files(&nodes, &data, content).unwrap();
        assert_eq!(decoded[0].path, PathBuf::from("payload.bin"));
        assert_eq!(decoded[0].data, plain);
    }
}

#[test]
fn real_encrypted_header_directory_and_chunk_boundaries() {
    let metadata: &[u8; 256] = STATES[..256].try_into().unwrap();
    let content = STATES[256..].try_into().unwrap();
    // Real stored tables have repeated values; requiring a permutation loses EVB.
    assert_eq!(
        metadata
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        160
    );
    let header = decipher(include_bytes!("fixtures/evb_header.bin"), metadata);
    assert_eq!(u32_at(&header, 20).unwrap(), 3);
    assert_eq!(u64_at(&header, 48).unwrap(), 0x196b7eb);
    let packed = include_bytes!("fixtures/evb_directory.bin");
    assert_eq!(u32_at(&decipher(&packed[..4], metadata), 0).unwrap(), 95);
    let expanded = u32_at(&decipher(&packed[4..8], metadata), 0).unwrap() as usize;
    let tree = codec::decompress(&decipher(&packed[8..], metadata), expanded, true).unwrap();
    let files = directory(&tree).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, PathBuf::from("Scene.pck"));
    assert_eq!(
        (files[0].offset, files[0].size, files[0].stored),
        (0, 26654476, 26654476)
    );
    let data = file_data(
        include_bytes!("fixtures/evb_content.bin"),
        16385,
        false,
        content,
    )
    .unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&data)),
        "2f84be9da56f8e25c400ba3dbc69caeb73953e53e10b0607bbc259eef48a4116"
    );
}

// Literal-only aPLib encoder for two independently compressed 64 KiB blocks.
fn literals(data: &[u8]) -> Vec<u8> {
    let mut result = vec![data[0]];
    let (mut tag, mut used) = (0, 8u8);
    let bit = |value: u8, result: &mut Vec<u8>, tag: &mut usize, used: &mut u8| {
        if *used == 8 {
            *tag = result.len();
            result.push(0);
            *used = 0;
        }
        result[*tag] |= value << (7 - *used);
        *used += 1;
    };
    for &byte in &data[1..] {
        bit(0, &mut result, &mut tag, &mut used);
        result.push(byte);
    }
    for value in [1, 1, 0] {
        bit(value, &mut result, &mut tag, &mut used);
    }
    result.push(0);
    result
}

#[test]
fn compressed_index_records_and_blocks_restart_independently() {
    let state = STATES[256..].try_into().unwrap();
    let first: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
    let second = b"last block";
    let blocks = [literals(&first), literals(second)];
    let mut stored = Vec::new();
    let mut offset = 24u64;
    for block in &blocks {
        let mut record = offset.to_le_bytes().to_vec();
        record.extend((block.len() as u32).to_le_bytes());
        stored.extend(decipher(&record, state));
        offset += block.len() as u64;
    }
    for block in blocks {
        stored.extend(decipher(&block, state));
    }
    let decoded = file_data(&stored, first.len() + second.len(), true, state).unwrap();
    assert_eq!(&decoded[..first.len()], first);
    assert_eq!(&decoded[first.len()..], second);
}

#[test]
fn storage_requires_one_complete_container_interpretation() {
    let state: &[u8; 256] = STATES[256..].try_into().unwrap();
    let node = |size, stored| Node {
        path: PathBuf::from("file.bin"),
        size,
        offset: 0,
        stored,
    };
    let packed = |block: &[u8]| {
        let mut index = 12u64.to_le_bytes().to_vec();
        index.extend((block.len() as u32).to_le_bytes());
        let mut bytes = decipher(&index, state);
        bytes.extend(decipher(block, state));
        bytes
    };
    let plain: Vec<_> = (0u8..128).collect();
    let raw = decipher(&plain, state);
    assert_eq!(
        stored_files(&[node(128, 128)], &raw, state).unwrap()[0].data,
        plain
    );

    // Compression may expand a file; stored < original is not a mode test.
    let expanded = packed(&literals(&plain));
    assert!(expanded.len() > plain.len());
    assert_eq!(
        stored_files(&[node(128, expanded.len())], &expanded, state).unwrap()[0].data,
        plain
    );
    // One long distance-1 match produces 128 A bytes, followed by termination.
    let mut block = vec![0x41, 0xaf, 0x01, 0xf6, 0xc0, 0];
    let small = packed(&block);
    assert_eq!(
        stored_files(&[node(128, small.len())], &small, state).unwrap()[0].data,
        vec![b'A'; 128]
    );

    // Native LZ permits block padding. Equal stored/original lengths can be
    // valid in both modes, so neither flag guessing nor mode preference is safe.
    block.resize(128 - 12, 0);
    let ambiguous = packed(&block);
    assert_eq!(ambiguous.len(), 128);
    assert!(
        stored_files(&[node(128, 128)], &ambiguous, state)
            .err()
            .unwrap()
            .to_string()
            .contains("ambiguous EVB storage")
    );

    let mut trailing = small.clone();
    trailing.push(0);
    assert!(stored_files(&[node(128, trailing.len())], &trailing, state).is_err());
    let mut invalid_lz = small.clone();
    *invalid_lz.last_mut().unwrap() ^= 0xff;
    assert!(stored_files(&[node(128, invalid_lz.len())], &invalid_lz, state).is_err());
    let mut gap = small.clone();
    let mut index = 13u64.to_le_bytes().to_vec();
    index.extend(6u32.to_le_bytes());
    gap[..12].copy_from_slice(&decipher(&index, state));
    assert!(stored_files(&[node(128, gap.len())], &gap, state).is_err());

    let mut mixed = small.clone();
    mixed.extend(&raw);
    let mut second = node(128, raw.len());
    second.offset = small.len();
    assert!(stored_files(&[node(128, small.len()), second], &mixed, state).is_err());
    assert!(
        stored_files(&[node(0, 0)], &[], state).unwrap()[0]
            .data
            .is_empty()
    );
    assert!(stored_files(&[], &[], state).unwrap().is_empty());
    assert!(file_data(&raw, 127, false, state).is_err());
}

#[test]
fn locate_uses_separate_u32_length_and_bias_fields() {
    let metadata: &[u8; 256] = STATES[..256].try_into().unwrap();
    let content: &[u8; 256] = STATES[256..].try_into().unwrap();
    let length = 184usize;

    let image = |container_at: usize, container: &[u8]| {
        let mut data = vec![0; 0x1000];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let nt = 0x80usize;
        data[nt..nt + 4].copy_from_slice(b"PE\0\0");
        data[nt + 4..nt + 6].copy_from_slice(&0x14cu16.to_le_bytes());
        data[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes());
        data[nt + 20..nt + 22].copy_from_slice(&224u16.to_le_bytes());
        let opt = nt + 24;
        data[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes());
        data[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        data[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        data[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        data[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        let section = opt + 224;
        data[section..section + 5].copy_from_slice(b".pack");
        data[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0x800u32.to_le_bytes());
        data[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
        data[container_at..container_at + container.len()].copy_from_slice(container);
        data
    };
    let mut header = vec![0; 64];
    header[4..8].copy_from_slice(&64u32.to_le_bytes());
    header[20..24].copy_from_slice(&3u32.to_le_bytes());
    header[24..32].copy_from_slice(&120u64.to_le_bytes());
    header[32..40].copy_from_slice(&((length - 120) as u64).to_le_bytes());
    header[48..56].copy_from_slice(&(length as u64).to_le_bytes());
    let mut container = vec![0; length];
    container[56..120].copy_from_slice(&decipher(&header, metadata));

    for skew in 0..4usize {
        let table = 0x100 + skew;
        let at = (table + 0x400).next_multiple_of(4);
        for version in [1u32, 3] {
            header[20..24].copy_from_slice(&version.to_le_bytes());
            container[56..120].copy_from_slice(&decipher(&header, metadata));
            for compressed in [0u8, 1, 0xff] {
                for bias in [0usize, 0x1e] {
                    let mut ctx = vec![0; 0x1000];
                    ctx[table..table + 0x100].copy_from_slice(metadata);
                    ctx[table + 0x100..table + 0x200].copy_from_slice(content);
                    ctx[at..at + 4].copy_from_slice(&(length as u32).to_le_bytes());
                    ctx[at + 4..at + 8].copy_from_slice(&(bias as u32).to_le_bytes());
                    ctx[table - 7] = compressed; // Former V1 compression rule.
                    ctx[table - 0x82] = compressed; // Former V3 compression rule.
                    ctx[table + 0x44c] = u8::from(compressed == 0); // Obsolete field.
                    let data = image(0x400 + bias, &container);
                    let parsed = Pe::parse(&data).unwrap();
                    let found = locate(&parsed, &ctx).unwrap().unwrap();
                    assert_eq!(
                        (found.table, found.base, found.length, found.version),
                        (table, 0x400 + bias, length, version)
                    );
                    if bias != 0 {
                        let wrong_start = image(0x400, &container);
                        assert!(
                            locate(&Pe::parse(&wrong_start).unwrap(), &ctx)
                                .unwrap()
                                .is_none()
                        );
                    }
                    // The same header with a different content-state source is ambiguous.
                    let duplicate = 0x800 + skew;
                    let state = ctx[table..table + 0x450].to_vec();
                    ctx[duplicate..duplicate + state.len()].copy_from_slice(&state);
                    ctx[duplicate + 0x100] ^= 1;
                    assert!(locate(&parsed, &ctx).is_err());

                    let data = image(0x400, &vec![0; length]);
                    let parsed = Pe::parse(&data).unwrap();
                    assert!(locate(&parsed, &ctx).unwrap().is_none());
                }
            }
        }
    }
}

#[test]
fn virtual_names_cannot_escape_output_directory() {
    for name in [
        "../outside",
        "C:\\outside",
        "\\outside",
        "%SYSTEM%\\outside",
        "dir\\..\\outside",
        "dir.\\outside",
        "NUL.txt",
    ] {
        let mut tree = vec![0; 12];
        for word in name.encode_utf16().chain([0]) {
            tree.extend(word.to_le_bytes());
        }
        tree.push(2);
        let error = directory(&tree).err().unwrap().to_string();
        assert!(error.contains("EVB path"), "{name}: {error}");
    }
}
