#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[test]
fn listings_preserve_full_x64_addresses_and_decode_the_selected_architecture() {
    let code = NativeCode {
        architecture: Architecture::X64,
        source: 0x1234,
        image_base: 0x140000000,
        rva: 0x2000,
        code: vec![
            0x49, 0xb8, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xc3,
        ],
        labels: [(0x2000, "vm_00001234".into())].into_iter().collect(),
        relocations: vec![0x2002],
    };
    let asm = code.assembly().unwrap();
    assert!(asm.contains("BITS 64\nORG 0x0000000140002000"));
    assert!(asm.contains("mov r8,0xfedcba9876543210"));
    assert!(asm.contains("DIR64 fixup RVAs: 0x2002"));
    let code = NativeCode {
        architecture: Architecture::X86,
        image_base: 0x400000,
        code: vec![0xb8, 1, 0, 0, 0, 0xc3],
        relocations: Vec::new(),
        ..code
    };
    let asm = code.assembly().unwrap();
    assert!(asm.contains("BITS 32\nORG 0x00402000"));
    assert!(asm.contains("mov eax,1"));
}
