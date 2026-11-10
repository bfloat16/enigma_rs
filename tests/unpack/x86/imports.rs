#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::common::{io::put_u32_at, pe::Section};

fn fixture() -> (Pe<'static>, Vec<Recovered>) {
    let sections = [(0x1000, 0x60000020), (0x2000, 0xc0000040)]
        .into_iter()
        .map(|(rva, characteristics)| Section {
            rva,
            virtual_size: 0x80,
            raw_offset: 0,
            raw_size: 0x80,
            characteristics,
            header_offset: 0,
        })
        .collect();
    let pe = Pe {
        data: &[],
        nt: 0,
        optional: 0,
        is_64: false,
        entry: 0x1000,
        image_base: 0x400000,
        image_size: 0x3000,
        headers_size: 0x200,
        file_alignment: 0x200,
        sections,
    };
    let recovered = [0x1000, 0x2000]
        .into_iter()
        .map(|rva| Recovered {
            rva,
            bytes: vec![0; 0x80],
        })
        .collect();
    (pe, recovered)
}

fn instruction(code: &mut [u8], at: usize, opcode: &[u8], slot: u32) -> u32 {
    code[at..at + opcode.len()].copy_from_slice(opcode);
    let operand = at + opcode.len();
    put_u32_at(code, operand, 0x400000 + slot).unwrap();
    0x1000 + operand as u32
}

#[test]
fn missing_iat_record_recovers_original_slot_from_multiple_code_uses() {
    // Real dword-flag record: winmm.dll!timeEndPeriod, a null slot followed
    // by two code operand references. Only the operand RVAs are relocated.
    let mut data = vec![
        0x01, 0, 0, 0, 0x09, 0, 0x82, 0x85, 0xe0, 0x8a, 0x4f, 0x93, 0x0f, 0xf7, 0xe0, 0x86, 0, 0,
        0, 0x0d, 0, 0x9c, 0x49, 0x9d, 0xb8, 0x5d, 0x0e, 0xc1, 0x4a, 0x65, 0x39, 0x62, 0x9b, 0x64,
        0x03, 0,
    ];
    data.resize(60, 0);
    data.extend(u32::MAX.to_le_bytes());
    let key = [
        0xe0, 0x28, 0xab, 0x11, 0x0b, 0x46, 0x88, 0x3d, 0x99, 0xb7, 0xea, 0x9e, 0xa7, 0xf8, 0xce,
        0x85,
    ];
    let (pe, mut recovered) = fixture();
    let call = instruction(&mut recovered[0].bytes, 0, &[0xff, 0x15], 0x2004);
    let jump = instruction(&mut recovered[0].bytes, 8, &[0xff, 0x25], 0x2004);
    put_u32_at(&mut data, 48, call).unwrap();
    put_u32_at(&mut data, 56, jump).unwrap();
    let parse = |data: &[u8]| {
        parse_records_with(data, &key, 4, false, |references| {
            resolve_references(&pe, &recovered, references)
        })
    };
    let imports = parse(&data).unwrap();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].dll, "winmm.dll");
    assert_eq!(imports[0].name.as_deref(), Some("timeEndPeriod"));
    assert_eq!(imports[0].iat_rva, 0x2004);
    let table = crate::unpack::rebuild::import_table(&imports, 0x3000, false).unwrap();
    assert_eq!(u32_at(&table.payload, 16).unwrap(), 0x2004);
    assert_ne!(table.patches[&0x2004], 0);
    assert_eq!(table.patches[&0x2008], 0);
    // The shared parser (including x64) still requires real IAT slots.
    assert!(crate::unpack::imports::parse_records(&data, &key, 4, false).is_err());
    assert!(parse(&data[..data.len() - 1]).is_err());
    let mut duplicate = data[..60].to_vec();
    duplicate.extend_from_slice(&data[15..]);
    assert!(
        parse(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate IAT")
    );
}

#[test]
fn code_references_support_calls_jumps_and_absolute_loads() {
    let (pe, mut recovered) = fixture();
    let mut references = vec![0];
    for (i, opcode) in [
        &[0xa1][..],
        &[0xff, 0x15],
        &[0xff, 0x25],
        &[0x8b, 0x05],
        &[0x8b, 0x0d],
        &[0x8b, 0x15],
        &[0x8b, 0x1d],
        &[0x8b, 0x25],
        &[0x8b, 0x2d],
        &[0x8b, 0x35],
        &[0x8b, 0x3d],
    ]
    .into_iter()
    .enumerate()
    {
        references.push(instruction(
            &mut recovered[0].bytes,
            i * 8,
            opcode,
            0x2004 + (i % 2) as u32 * 4,
        ));
    }
    assert_eq!(
        resolve_references(&pe, &recovered, &references).unwrap(),
        [0x2004, 0x2008]
    );
    assert_eq!(
        resolve_references(&pe, &recovered, &[0x2004, 0x2008]).unwrap(),
        [0x2004, 0x2008]
    );
}

#[test]
fn missing_iat_references_reject_invalid_operands_and_targets() {
    let (mut pe, mut recovered) = fixture();
    let operand = instruction(&mut recovered[0].bytes, 0, &[0xff, 0x15], 0x2004);
    for references in [
        vec![0],
        vec![0, 0],
        vec![0, 1],
        vec![0, operand, operand],
        vec![0, 0x107e],
        vec![0, 0x3002],
    ] {
        assert!(resolve_references(&pe, &recovered, &references).is_err());
    }
    for va in [0, 0x400000, 0x402005, 0x402080, 0x403000] {
        put_u32_at(&mut recovered[0].bytes, 2, va).unwrap();
        assert!(resolve_references(&pe, &recovered, &[0, operand]).is_err());
    }
    instruction(&mut recovered[0].bytes, 0, &[0xff, 0x35], 0x2004);
    assert!(resolve_references(&pe, &recovered, &[0, operand]).is_err());
    instruction(&mut recovered[0].bytes, 0, &[0x8b, 0x45], 0x2004);
    assert!(resolve_references(&pe, &recovered, &[0, operand]).is_err());
    instruction(&mut recovered[0].bytes, 0, &[0xff, 0x15], 0x2004);
    pe.sections[0].characteristics &= !0x20000000;
    assert!(resolve_references(&pe, &recovered, &[0, operand]).is_err());
}
