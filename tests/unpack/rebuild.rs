#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::common::pe::Section;

fn image(data: &[u8]) -> Pe<'_> {
    Pe {
        data,
        nt: 0,
        optional: 0,
        is_64: true,
        entry: 0x1000,
        image_base: 0x140000000,
        image_size: 0x3000,
        headers_size: 0x200,
        file_alignment: 0x200,
        sections: vec![Section {
            rva: 0x1000,
            virtual_size: 0x400,
            raw_offset: 0x200,
            raw_size: 0x200,
            characteristics: 0xc0000040,
            header_offset: 0,
        }],
    }
}

#[test]
fn tls_template_preserves_file_bytes_and_zero_fills_only_virtual_tail() {
    let mut data = vec![0xaa; 0x600];
    data[0x3fe..0x400].copy_from_slice(&[0x12, 0x34]);
    let mut pe = image(&data);
    assert_eq!(
        &*tls_template(&pe, 0x11fc, 4).unwrap(),
        &[0xaa, 0xaa, 0x12, 0x34]
    );
    assert_eq!(
        &*tls_template(&pe, 0x11fe, 6).unwrap(),
        &[0x12, 0x34, 0, 0, 0, 0]
    );
    assert_eq!(&*tls_template(&pe, 0x13fe, 2).unwrap(), &[0; 2]);
    assert!(pe.read(0x11fe, 6).is_err());
    pe.sections[0].raw_size = 0;
    assert_eq!(&*tls_template(&pe, 0x1000, 0x48).unwrap(), &[0; 0x48]);
    assert!(tls_template(&pe, 0, 0).unwrap().is_empty());
}

#[test]
fn tls_template_rejects_unmapped_ranges_and_truncated_file_data() {
    let data = vec![0xaa; 0x3ff];
    let mut pe = image(&data);
    assert!(tls_template(&pe, 0x11fe, 6).is_err());
    assert!(tls_template(&pe, 0x13fe, 4).is_err());
    assert!(tls_template(&pe, 0x2000, 1).is_err());
    assert!(tls_template(&pe, u32::MAX, 2).is_err());
    assert!(tls_template(&pe, 0x1000, 0x3001).is_err());
    pe.sections.push(Section {
        rva: 0x1300,
        virtual_size: 0,
        raw_offset: 0,
        raw_size: 0,
        characteristics: 0,
        header_offset: 0,
    });
    assert_eq!(&*tls_template(&pe, 0x12fe, 4).unwrap(), &[0; 4]);
    pe.sections[1].virtual_size = 0x100;
    assert!(tls_template(&pe, 0x12fe, 4).is_err());
    pe.image_size = 0x13ff;
    assert!(tls_template(&pe, 0x13fe, 2).is_err());
}
