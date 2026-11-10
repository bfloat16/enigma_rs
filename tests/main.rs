#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn modes_preserve_unpack_and_parse_hex_rvas() {
    let unpack = Args::try_parse_from(["enigma-rs", "input.exe", "--mod", "cpu"]).unwrap();
    assert_eq!(unpack.mode, Mode::Unpack);
    assert!(unpack.validate().unwrap().is_none());
    for value in ["0x23B053", "0X23b053", "23b053"] {
        let args = Args::try_parse_from([
            "enigma-rs",
            "input.exe",
            "--mode",
            "devirt",
            value,
            "-o",
            "result.asm",
        ])
        .unwrap();
        assert_eq!(args.validate().unwrap(), Some(0x23b053));
    }
    let scan = Args::try_parse_from(["enigma-rs", "input.exe", "--mode", "scan"]).unwrap();
    assert!(scan.validate().unwrap().is_none());
    let runtime = Args::try_parse_from([
        "enigma-rs",
        "input.exe",
        "--mode",
        "runtime",
        "-o",
        "runtime.dll",
    ])
    .unwrap();
    assert!(runtime.validate().unwrap().is_none());
}

#[test]
fn inconsistent_modes_fail_before_opening_input() {
    for args in [
        vec!["enigma-rs", "input.exe", "output.exe"],
        vec!["enigma-rs", "input.exe", "-o", "output.exe"],
        vec!["enigma-rs", "input.exe", "--mode", "devirt"],
        vec!["enigma-rs", "input.exe", "--mode", "devirt", "100000000"],
        vec!["enigma-rs", "input.exe", "--mode", "scan", "--mod", "cpu"],
        vec!["enigma-rs", "input.exe", "--mode", "scan", "1234"],
        vec!["enigma-rs", "input.exe", "--mode", "runtime", "1234"],
        vec![
            "enigma-rs",
            "input.exe",
            "--mode",
            "runtime",
            "--mod",
            "cuda",
        ],
    ] {
        assert!(Args::try_parse_from(args).unwrap().validate().is_err());
    }
}
