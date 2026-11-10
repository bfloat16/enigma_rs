#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use iced_x86::code_asm::*;

fn run(bytes: Vec<u8>, mut state: State) -> State {
    let mut image = Image::default();
    image.add(state.pc, bytes).unwrap();
    for _ in 0..100 {
        let i = image.instruction(state.pc).unwrap();
        if i.mnemonic() == M::Ret {
            return state;
        }
        assert!(execute(&mut state, &image, &i).unwrap().is_none());
    }
    panic!("test instruction limit")
}

#[test]
fn wide_registers_rip_addresses_and_partial_writes_preserve_x64_semantics() {
    let base = 0x140001000;
    let mut code = CodeAssembler::new(64).unwrap();
    code.mov(rax, 0x123456789abcdef0u64).unwrap();
    code.mov(ah, 0x55u32).unwrap();
    code.mov(r8, rax).unwrap();
    code.mov(eax, 0xaabbccddu32).unwrap();
    code.mov(r9, rax).unwrap();
    code.bswap(eax).unwrap();
    code.ret().unwrap();
    let mut b = code.assemble(base).unwrap();
    b.pop();
    b.extend([0x4c, 0x8d, 0x15, 0x34, 0x12, 0, 0, 0xc3]);
    let lea = Decoder::with_ip(64, &b, base, DecoderOptions::NONE)
        .into_iter()
        .find(|i| i.mnemonic() == M::Lea)
        .unwrap();
    assert!(lea.is_ip_rel_memory_operand());
    let s = run(b, State::new(base, 0x200100000));
    assert_eq!(s.registers[8].get(), Some(0x123456789abc55f0));
    assert_eq!(s.registers[9].get(), Some(0xaabbccdd));
    assert_eq!(s.registers[0].get(), Some(0xddccbbaa));
    assert_eq!(s.registers[10].get(), Some(lea.ip_rel_memory_address()));
}

#[test]
fn qword_spills_preserve_all_symbolic_registers() {
    let mut code = CodeAssembler::new(64).unwrap();
    code.push(r15).unwrap();
    code.pushfq().unwrap();
    code.pop(r8).unwrap();
    code.pop(r9).unwrap();
    code.ret().unwrap();
    let initial = State::new(0x140001000, 0x200100000);
    let result = run(code.assemble(initial.pc).unwrap(), initial.clone());
    assert_eq!(result.registers[8], initial.flags);
    assert_eq!(result.registers[9], initial.registers[15]);
    assert_eq!(result.esp().unwrap(), initial.esp().unwrap());
}

#[test]
fn qword_arithmetic_uses_full_width_carry_rotate_and_product() {
    let mut code = CodeAssembler::new(64).unwrap();
    code.mov(rax, u64::MAX).unwrap();
    code.add(rax, 1).unwrap();
    code.setb(bl).unwrap();
    code.mov(rax, 1u64).unwrap();
    code.rol(rax, 63).unwrap();
    code.mov(r8, rax).unwrap();
    code.mov(rax, u64::MAX).unwrap();
    code.mov(rcx, 2u64).unwrap();
    code.mul(rcx).unwrap();
    code.ret().unwrap();
    let s = run(
        code.assemble(0x140001000).unwrap(),
        State::new(0x140001000, 0x200100000),
    );
    assert_eq!(reg(&s, R::BL).unwrap().get(), Some(1));
    assert_eq!(s.registers[8].get(), Some(1 << 63));
    assert_eq!(s.registers[0].get(), Some(u64::MAX - 1));
    assert_eq!(s.registers[2].get(), Some(1));
}

#[test]
fn unknown_x64_branches_are_explored_instead_of_using_initial_flags() {
    let mut code = CodeAssembler::new(64).unwrap();
    let mut other = code.create_label();
    let mut end = code.create_label();
    code.jz(other).unwrap();
    code.mov(r8, 1u64).unwrap();
    code.jmp(end).unwrap();
    code.set_label(&mut other).unwrap();
    code.mov(r8, 2u64).unwrap();
    code.set_label(&mut end).unwrap();
    code.ret().unwrap();
    let mut image = Image::default();
    image
        .add(0x140001000, code.assemble(0x140001000).unwrap())
        .unwrap();
    let mut values = Vec::new();
    analyze(
        &mut image,
        State::new(0x140001000, 0x200100000),
        |image, state| {
            if image.instruction(state.pc)?.mnemonic() == M::Ret {
                values.push(state.registers[8].get().unwrap());
                Ok(Action::Finish)
            } else {
                Ok(Action::Decode)
            }
        },
    )
    .unwrap();
    values.sort_unstable();
    values.dedup();
    assert_eq!(values, [1, 2]);
}
