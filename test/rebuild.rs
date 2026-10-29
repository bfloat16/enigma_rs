use super::*;
use crate::common::pe::Section;

fn descriptor(rva: u32, characteristics: u32) -> super::super::config::Descriptor {
    super::super::config::Descriptor {
        index: 0,
        enabled: true,
        flags: 0xf,
        packed_size: 0,
        expanded_size: 0x100,
        rva,
        characteristics,
        seed: [0; 16],
        crc32: 0,
    }
}

#[test]
fn original_section_permissions_follow_rva_not_descriptor_order_or_encryption() {
    let pe = image(&[]);
    let mut writable = descriptor(0x1000, 0xc0000040);
    writable.enabled = false;
    let read_only = descriptor(0x3000, 0x40000040);
    let flags = original_section_flags(&pe, &[read_only, writable], 0x4000).unwrap();
    assert_eq!(flags[&0x3000], 0x40000040);
    assert_eq!(flags[&0x1000], 0xc0000040);
    let flags = original_section_flags(&pe, &[descriptor(0x1000, 0x60000020)], 0x4000).unwrap();
    assert_eq!(flags[&0x1000], 0x60000020);
    assert!(!flags.contains_key(&0x3000)); // No permission guesses for other sections.
}

#[test]
fn original_section_permissions_reject_ambiguous_and_nonsection_targets() {
    let pe = image(&[]);
    for rva in [0x1001, 0x2000, 0x4000] {
        assert!(original_section_flags(&pe, &[descriptor(rva, 0x40000040)], 0x4000).is_err());
    }
    assert!(original_section_flags(&pe, &[descriptor(0x3000, 0x40000040)], 0x3000).is_err());
    assert!(
        original_section_flags(
            &pe,
            &[
                descriptor(0x1000, 0x40000040),
                descriptor(0x1000, 0xc0000040),
            ],
            0x4000
        )
        .is_err()
    );
    let flags = original_section_flags(&pe, &[descriptor(0, 0), descriptor(0x12345678, 0)], 0x4000)
        .unwrap();
    assert!(flags.is_empty());
}

#[test]
#[ignore = "requires ENIGMA_CRT_IMAGE and independently established CRT check/stop/slot RVAs"]
fn sample_crt_nonwritable_gate_uses_restored_pe_permissions() {
    use crate::devirt::static_x86::{self, Image, State, Value};
    let bytes = std::fs::read(std::env::var_os("ENIGMA_CRT_IMAGE").unwrap()).unwrap();
    let pe = Pe::parse(&bytes).unwrap();
    let rva = |name| u32::from_str_radix(&std::env::var(name).unwrap(), 16).unwrap();
    let check = rva("ENIGMA_CRT_CHECK_RVA");
    let stop = rva("ENIGMA_CRT_STOP_RVA");
    let slot = rva("ENIGMA_CRT_SLOT_RVA");
    let section = pe.section_at(slot).unwrap();
    assert_eq!(section.characteristics & 0x80000000, 0);
    let base = u32::try_from(pe.image_base).unwrap();
    for writable in [false, true] {
        let mut headers = bytes[..pe.headers_size as usize].to_vec();
        if writable {
            put(
                &mut headers,
                section.header_offset + 36,
                section.characteristics | 0x80000000,
            )
            .unwrap();
        }
        let mut image = Image::default();
        image.add(base, headers).unwrap();
        for section in &pe.sections {
            if section.raw_size != 0 {
                image
                    .add(
                        base + section.rva,
                        pe.read(section.rva, section.raw_size as usize)
                            .unwrap()
                            .to_vec(),
                    )
                    .unwrap();
            }
        }
        // Begin at the pure PE check after the SEH prologue, stop before its
        // epilogue. Interpret input instructions; never invoke target code.
        let mut state = State::new(base + check, 0x20080000);
        state.registers[5] = Value::constant(0x20081000);
        state.write(&image, 0x20081008, 4, Value::constant(base + slot));
        let mut reached = false;
        for _ in 0..2000 {
            if state.pc == base + stop {
                assert_eq!(state.registers[0].get(), Some(u32::from(!writable)));
                reached = true;
                break;
            }
            let instruction = image.instruction(state.pc).unwrap();
            assert!(
                static_x86::execute(&mut state, &image, &instruction)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(reached, "CRT permission check did not reach its result");
    }
}

fn image(data: &[u8]) -> Pe<'_> {
    Pe {
        data,
        nt: 0,
        optional: 0x80,
        is_64: false,
        entry: 0x1000,
        image_base: 0x400000,
        image_size: 0x5000,
        headers_size: 0x200,
        file_alignment: 0x200,
        sections: vec![
            Section {
                rva: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x200,
                raw_size: 0x200,
                characteristics: 0xe0000040,
                header_offset: 0,
            },
            Section {
                rva: 0x3000,
                virtual_size: 0x1000,
                raw_offset: 0x400,
                raw_size: 0x400,
                characteristics: 0xe0000040,
                header_offset: 0,
            },
        ],
    }
}

fn tls_fixture() -> (Vec<u8>, Vec<u8>) {
    let mut data = vec![0; 0x800];
    put(&mut data, 0x80 + 96 + 72, 0x3000).unwrap();
    put(&mut data, 0x80 + 96 + 76, 24).unwrap();
    for (i, value) in [0x403040, 0x40304c, 0x403018, 0x403030, 8, 0x500000]
        .into_iter()
        .enumerate()
    {
        put(&mut data, 0x400 + i * 4, value).unwrap();
    }
    put(&mut data, 0x430, 0x401020).unwrap();
    data[0x440..0x44c].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0]);
    let mut ctx = vec![0; 0x400];
    // The host index is in its zero-filled virtual extent, not file-backed data.
    put(&mut ctx, 0x384, 0x1f00).unwrap();
    put(&mut ctx, 0x388, 0x3018).unwrap();
    (data, ctx)
}

#[test]
fn tls_restores_template_host_index_callbacks_and_rebase_fixups() {
    let (data, ctx) = tls_fixture();
    let pe = image(&data);
    let mut payload = vec![0xaa; 3];
    let (rva, fixups) = append_tls(&pe, &ctx, 0x384, 0x2000, 0x2000, &mut payload).unwrap();
    let at = (rva - 0x2000) as usize;
    let template = (u32_at(&payload, at).unwrap() - 0x402000) as usize;
    let callbacks = (u32_at(&payload, at + 12).unwrap() - 0x402000) as usize;
    assert_eq!((0x402000 + template) % 16, 0);
    assert_eq!(
        u32_at(&payload, at + 4).unwrap(),
        0x402000 + template as u32 + 12
    );
    assert_eq!(u32_at(&payload, at + 8).unwrap(), 0x401f00);
    assert_eq!(&payload[template..template + 12], &data[0x440..0x44c]);
    assert_eq!(u32_at(&payload, at + 16).unwrap(), 8);
    assert_eq!(u32_at(&payload, at + 20).unwrap(), 0x500000);
    assert_eq!(u32_at(&payload, callbacks).unwrap(), 0x401020);
    assert_eq!(u32_at(&payload, callbacks + 4).unwrap(), 0);
    assert_eq!(
        fixups,
        [rva, rva + 4, rva + 8, rva + 12, 0x2000 + callbacks as u32]
    );
    // Apply a base delta at exactly those sites, as the Windows loader does.
    for rva in fixups {
        let at = (rva - 0x2000) as usize;
        let value = u32_at(&payload, at).unwrap() + 0x100000;
        put(&mut payload, at, value).unwrap();
    }
    assert_eq!(u32_at(&payload, at + 8).unwrap(), 0x501f00);
    assert_eq!(u32_at(&payload, callbacks).unwrap(), 0x501020);
    assert_eq!(u32_at(&payload, callbacks + 4).unwrap(), 0);
}

#[test]
fn tls_rejects_removed_loader_callbacks_and_wrong_index_mapping() {
    let (mut data, ctx) = tls_fixture();
    put(&mut data, 0x430, 0x403100).unwrap();
    assert!(append_tls(&image(&data), &ctx, 0x384, 0x2000, 0x2000, &mut Vec::new()).is_err());
    put(&mut data, 0x430, 0).unwrap();
    put(&mut data, 0x408, 0x40301c).unwrap();
    assert!(append_tls(&image(&data), &ctx, 0x384, 0x2000, 0x2000, &mut Vec::new()).is_err());
}
