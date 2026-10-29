use super::*;
use crate::common::io::put_u32_at;

#[test]
fn encrypted_entry_fields_follow_hash_and_in_place_cipher_operands() {
    let image = vec![0; 0x400];
    let mut records = vec![vec![0; 72]; 31];
    let mut token = |index: usize, op: u32, dest: u32, kind: u32, base: u32, value: u32| {
        let raw = &mut records[index];
        for (at, value) in [
            (0, op),
            (12, 0x8c),
            (16, 0x25 + dest),
            (24, 0x2000),
            (32, kind),
            (36, base),
            (44, 0x2000),
            (48, value),
        ] {
            put_u32_at(raw, at, value).unwrap();
        }
    };
    for (index, op, dest, kind, base, value) in [
        (1, 0x4d, 0, 0x8d, 0x27, 0x100),
        (4, 0x4d, 0, 0x8d, 0x27, 0x180),
        (5, 0x4d, 0, 0x8f, 0, 24),
        (6, 0x51, 1, 0x8d, 0x2a, 0xffffffd8),
        (9, 0x52, 2, 0x8d, 0x27, 0x2a0),
        (11, 0x51, 0, 0x8d, 0x2a, 0xffffffd8),
        (12, 0x5a, 0, 0, 0, 0),
        (15, 0x51, 2, 0x8d, 0x25, 0x200),
        (18, 0x4d, 0, 0x8f, 0, 0x200),
        (19, 0x52, 1, 0x8f, 0, 4),
        (26, 0x51, 2, 0x8d, 0x25, 0x290),
        (27, 0x51, 0, 0x8d, 0x2a, 0xffffffd8),
        (28, 0x52, 1, 0x8f, 0, 16),
    ] {
        token(index, op, dest, kind, base, value);
    }
    for index in [10, 20, 29] {
        put_u32_at(&mut records[index], 0, 0x60).unwrap();
        put_u32_at(&mut records[index], 12, 0x90).unwrap();
        put_u32_at(&mut records[index], 28, 0x100).unwrap();
    }
    for case in 0..3 {
        if case == 1 {
            put_u32_at(&mut records[11], 48, 0xffffffd4).unwrap();
        }
        if case == 2 {
            put_u32_at(&mut records[11], 48, 0xffffffd8).unwrap();
            put_u32_at(&mut records[26], 48, 0x2f4).unwrap();
        }
        let tokens = Tokens {
            dispatch: 0,
            key: 0,
            serialized: 0,
            image: &image,
            records: records.iter().map(Vec::as_slice).collect(),
        };
        let result = tokens.entry_cipher(0x100, 0x200, 0x300);
        match case {
            0 => {
                let fields = result.unwrap().unwrap();
                assert_eq!(
                    (fields.offset, fields.bias, fields.length, fields.digest),
                    (0x180, 24, 0x2a0, 0x290)
                );
            }
            1 => assert!(result.unwrap().is_none()),
            _ => assert!(result.is_err()),
        }
    }
}

#[test]
fn configuration_projection_uses_copy_semantics_not_a_minimum_field_offset() {
    let mut image = vec![0; 0x400];
    image[0x100..0x107].copy_from_slice(&[0x92, 0xe8, 0xfa, 0, 0, 0, 0xc3]);
    image[0x200..0x205].copy_from_slice(&[0xf3, 0xa5, 0xf3, 0xa4, 0xc3]);
    let expected = vec![(0x80, 0x40), (0xc0, 0x80), (0x140, 0x1200)];
    let mut records = vec![vec![0; 72]; 21];
    for (block, &(offset, size)) in expected.iter().enumerate() {
        for (n, op, dest, kind, source, value) in [
            (0, 0x52, 3, 0x8f, 0, size),
            (1, 0x52, 0, 0x8c, 0x2c, 0),
            (2, 0x4d, 0, 0x8f, 0, offset),
            (3, 0x52, 1, 0x8c, 0x28, 0),
            (4, 0x52, 2, 0x8c, 0x2b, 0),
            (6, 0x4d, 6, 0x8c, 0x28, 0),
        ] {
            let raw = &mut records[block * 7 + n];
            for (at, value) in [
                (0, op),
                (12, 0x8c),
                (16, 0x25 + dest),
                (24, 0x2000),
                (32, kind),
                (36, source),
                (44, 0x2000),
                (48, value as u32),
            ] {
                put_u32_at(raw, at, value).unwrap();
            }
        }
        let call = &mut records[block * 7 + 5];
        put_u32_at(call, 0, 0x60).unwrap();
        put_u32_at(call, 12, 0x90).unwrap();
        put_u32_at(call, 28, 0x100).unwrap();
    }
    for wrong_direction in [false, true] {
        if wrong_direction {
            for block in 0..3 {
                put_u32_at(&mut records[block * 7 + 4], 16, 0x25).unwrap();
            }
        }
        let tokens = Tokens {
            dispatch: 0,
            key: 0,
            serialized: 0,
            image: &image,
            records: records.iter().map(Vec::as_slice).collect(),
        };
        if wrong_direction {
            assert!(tokens.projection().is_err());
        } else {
            assert_eq!(tokens.projection().unwrap(), expected);
        }
    }
}

fn registry(ambiguous: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut image = vec![0; 0x4000];
    let mut records = vec![vec![0; 72]; 11];
    let mut token =
        |index: usize, op: u32, left: (u32, u32, u32, u32), right: (u32, u32, u32, u32)| {
            let bytes = &mut records[index];
            put_u32_at(bytes, 0, op).unwrap();
            for (at, value) in [
                (12, left.0),
                (16, left.1),
                (24, left.2),
                (28, left.3),
                (32, right.0),
                (36, right.1),
                (44, right.2),
                (48, right.3),
            ] {
                put_u32_at(bytes, at, value).unwrap();
            }
        };
    let none = (0, 0, 0, 0);
    token(0, 0x52, (0x8c, 0x2b, 0x2000, 0), (0x8f, 0, 0x2000, 2));
    token(1, 0x52, (0x8c, 0x28, 0x2000, 0), (0x8d, 0, 0x202001, 0x100));
    token(2, 0x52, (0x8c, 0x25, 0x2000, 0), (0x8d, 0, 0x202001, 0x104));
    token(3, 0x4d, (0x8c, 0x25, 0x2000, 0), (0x8f, 0, 0x2000, 4));
    token(5, 0x50, (0x8d, 0x28, 0x800, 0), (0x8f, 0, 0x800, 0));
    token(
        7,
        0x4d,
        (0x8d, 0x2a, 0x2000, 0xfffffff8),
        (0x8f, 0, 0x2000, 8),
    );
    token(8, 0x4d, (0x8c, 0x28, 0x2000, 0), (0x8f, 0, 0x2000, 20));
    token(9, 1, (0x8c, 0x2b, 0x2000, 0), none);
    token(10, 0x2d, (0x90, 0, 0x800, 5), none);
    put_u32_at(&mut image, 0x100, BASE + 0x2000).unwrap();
    put_u32_at(&mut image, 0x104, BASE + 0x2200).unwrap();
    image[0x2400..0x240d].copy_from_slice(b"kernel32.dll\0");
    for (i, name) in [b"LoadLibraryA\0".as_slice(), b"GetProcAddress\0".as_slice()]
        .into_iter()
        .enumerate()
    {
        let at = 0x2420 + i * 32;
        image[at..at + name.len()].copy_from_slice(name);
        put_u32_at(&mut image, 0x2200 + i * 8, BASE + 0x2400).unwrap();
        put_u32_at(&mut image, 0x2204 + i * 8, BASE + at as u32).unwrap();
        let implementation = 0x3000 + i * 32;
        let stub = 0x3100 + i * 32;
        put_u32_at(&mut image, 0x2004 + i * 20, BASE + implementation as u32).unwrap();
        if ambiguous {
            put_u32_at(&mut image, 0x2008 + i * 20, BASE + implementation as u32).unwrap();
        }
        image[implementation] = 0xe9;
        put_u32_at(
            &mut image,
            implementation + 1,
            (stub as u32).wrapping_sub(implementation as u32 + 5),
        )
        .unwrap();
        image[stub] = 0x68;
        put_u32_at(&mut image, stub + 1, i as u32 ^ 0xabcdef01).unwrap();
        image[stub + 5] = 0xe9;
        put_u32_at(
            &mut image,
            stub + 6,
            0x400u32.wrapping_sub(stub as u32 + 10),
        )
        .unwrap();
    }
    (image, records)
}

#[test]
fn hook_registry_derives_count_stride_and_function_column() {
    for ambiguous in [false, true] {
        let (image, records) = registry(ambiguous);
        let tokens = Tokens {
            dispatch: 0x400,
            key: 0xabcdef01,
            records: records.iter().map(Vec::as_slice).collect(),
            serialized: 0,
            image: &image,
        };
        let result = tokens.hooks();
        if ambiguous {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("replacement column")
            );
        } else {
            let hooks = result.unwrap();
            assert_eq!(hooks.len(), 2);
            assert_eq!(hooks[&0], ("kernel32.dll".into(), "LoadLibraryA".into()));
            assert_eq!(hooks[&1], ("kernel32.dll".into(), "GetProcAddress".into()));
        }
    }
}
