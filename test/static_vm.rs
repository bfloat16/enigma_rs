use enigma_rs::devirt::vm;

const STUB: usize = 0x1000;
const DISPATCH: usize = 0x15aa34;
fn image(code: &[u8]) -> Vec<u8> {
    let mut b = vec![0; DISPATCH + 16];
    b[STUB..STUB + code.len()].copy_from_slice(code);
    b
}
fn transfer(code: &mut Vec<u8>) {
    let next = STUB + code.len() + 5;
    code.push(0xe9);
    code.extend((DISPATCH as u32).wrapping_sub(next as u32).to_le_bytes());
}
#[test]
fn static_iat_stub_resolves_all_initial_registers_and_flags() {
    let key: u32 = 0x12345678;
    let token: u32 = 0x71a3;
    let mut code = vec![0xb8];
    code.extend((key ^ token).to_le_bytes());
    code.extend([0xc1, 0xc8, 17, 0xc1, 0xc0, 17, 0x50]);
    transfer(&mut code);
    assert_eq!(
        vm::stub_token_at(&image(&code), STUB as u32, key, DISPATCH as u32).unwrap(),
        token
    );
}
#[test]
fn static_iat_stub_rejects_ambiguous_or_input_dependent_tokens() {
    // JE chooses two different encoded constants; no concrete flags are seeded.
    let mut code = vec![0x74, 7, 0xb8, 1, 0, 0, 0, 0xeb, 5, 0xb8, 2, 0, 0, 0, 0x50];
    transfer(&mut code);
    assert!(vm::stub_token_at(&image(&code), STUB as u32, 0, DISPATCH as u32).is_err());
    let mut code = vec![0x50];
    transfer(&mut code); // Unknown initial EAX.
    assert!(vm::stub_token_at(&image(&code), STUB as u32, 0, DISPATCH as u32).is_err());
}
