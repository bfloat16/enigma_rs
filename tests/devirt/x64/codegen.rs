#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::devirt::x64::{
    cpu::{self, Image, State, Value},
    graph::Graph,
    switch::Session,
};

const BASE: u64 = 0x140000000;
const RVA: u64 = 0x10000;
const STACK: u64 = 0x300080000;
const STOP: u64 = 0x500000000;

fn execute(program: &Program, delta: u64, input: [u64; 16], flags: u64) -> State {
    let mut image = Image::default();
    let mut bytes = program.bytes.clone();
    for &site in &program.relocations {
        let at = (site - RVA) as usize;
        let value = crate::common::io::u64_at(&bytes, at).unwrap();
        put_u64_at(&mut bytes, at, value + delta).unwrap();
    }
    image.add(BASE + delta + RVA, bytes).unwrap();
    image.zero(STACK - 0x100000, 0x200000);
    let mut state = State::new(
        BASE + delta + program.entries[&Start::Function(0x1000)],
        STACK,
    );
    state.registers = input.map(Value::constant);
    state.registers[4] = Value::constant(STACK);
    state.flags = Value::constant(flags);
    state.write(&image, STACK, 8, Value::constant(STOP));
    state.write(
        &image,
        STACK + 0x1000,
        8,
        Value::constant(0xfedcba9876543210),
    );
    for _ in 0..200000 {
        if state.pc == STOP {
            return state;
        }
        let i = image.instruction(state.pc).unwrap();
        assert!(cpu::execute(&mut state, &image, &i).unwrap().is_none());
    }
    panic!("generated x64 did not return")
}

fn recovered(bytes: Vec<u8>, inputs: &[[u64; 16]]) {
    let session = Session::synthetic_program(bytes.clone());
    let mut graph = Graph::recover_session(session, Start::Function(0x1000)).unwrap();
    super::super::optimize::run(&mut graph).unwrap();
    let function = RecoveredFunction::from(graph);
    let program = emit(
        &[Function::from(&function)],
        BASE,
        RVA,
        &super::super::budget::Budget::new().unwrap(),
    )
    .unwrap();
    let reference = Program {
        bytes,
        entries: [(Start::Function(0x1000), RVA)].into_iter().collect(),
        relocations: Vec::new(),
    };
    for &input in inputs {
        let expected = execute(&reference, 0, input, 0x203);
        for delta in [0, 0x100000000] {
            let actual = execute(&program, delta, input, 0x203);
            assert_eq!(
                actual.registers.map(Value::get),
                expected.registers.map(Value::get)
            );
            assert_eq!(
                actual.flags.known & expected.flags.known,
                expected.flags.known
            );
            assert_eq!(
                (actual.flags.bits ^ expected.flags.bits) & expected.flags.known,
                0
            );
        }
    }
}

#[test]
fn recovered_x64_preserves_qword_operations_partial_registers_and_all_gprs() {
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(r8, 0x123456789abcdef0u64).unwrap();
    a.mov(ah, 0x55u32).unwrap();
    a.add(rax, r8).unwrap();
    a.mov(r9d, eax).unwrap();
    a.ror(r8, 40).unwrap();
    a.movsxd(r10, r9d).unwrap();
    a.bswap(r11d).unwrap();
    a.ret().unwrap();
    recovered(
        a.assemble(BASE + RVA).unwrap(),
        &[
            std::array::from_fn(|n| 0x8877665544332211u64.wrapping_mul(n as u64 + 1)),
            [u64::MAX; 16],
        ],
    );
}

#[test]
fn recovered_x64_joins_qword_spills_and_keeps_guest_loop_branches() {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut other = a.create_label();
    let mut join = a.create_label();
    let mut loop_at = a.create_label();
    a.sub(rsp, 16).unwrap();
    a.test(rbx, rbx).unwrap();
    a.je(other).unwrap();
    a.mov(qword_ptr(rsp + 1), r8).unwrap();
    a.jmp(join).unwrap();
    a.set_label(&mut other).unwrap();
    a.mov(qword_ptr(rsp + 1), r9).unwrap();
    a.set_label(&mut join).unwrap();
    a.mov(rax, qword_ptr(rsp + 1)).unwrap();
    a.mov(ecx, 4u32).unwrap();
    a.set_label(&mut loop_at).unwrap();
    a.add(rax, r10).unwrap();
    a.dec(ecx).unwrap();
    a.jne(loop_at).unwrap();
    a.add(rsp, 16).unwrap();
    a.ret().unwrap();
    let mut inputs = [[0u64; 16]; 2];
    for (n, input) in inputs.iter_mut().enumerate() {
        input[3] = n as u64;
        input[8] = 0x1122334455667788;
        input[9] = 0xffeeddccbbaa9988;
        input[10] = 0x100000003;
    }
    // Synthetic recovery uses RVA 0x1000; direct branch instructions are relative.
    recovered(a.assemble(BASE + RVA).unwrap(), &inputs);
}

#[test]
fn recovered_x64_shifts_keep_operand_width_and_zero_count_flags() {
    for width in [8, 16, 32, 64] {
        for op in [M::Shl, M::Shr, M::Sar, M::Rol, M::Ror] {
            let mut a = CodeAssembler::new(64).unwrap();
            macro_rules! shift {
                ($method:ident) => {
                    match width {
                        8 => a.$method(al, cl).unwrap(),
                        16 => a.$method(ax, cl).unwrap(),
                        32 => a.$method(eax, cl).unwrap(),
                        _ => a.$method(rax, cl).unwrap(),
                    }
                };
            }
            match op {
                M::Shl => shift!(shl),
                M::Shr => shift!(shr),
                M::Sar => shift!(sar),
                M::Rol => shift!(rol),
                M::Ror => shift!(ror),
                _ => unreachable!(),
            }
            a.ret().unwrap();
            let inputs = [0, 1, 8, 16, 31, 32, 63, 64, 65, 255].map(|count| {
                let mut values = [0x8000000080008081; 16];
                values[1] = count;
                values
            });
            recovered(a.assemble(BASE + RVA).unwrap(), &inputs);
        }
    }
}

#[test]
fn recovered_x64_multiply_high_word_and_constant_signed_division() {
    let mut a = CodeAssembler::new(64).unwrap();
    a.mul(rcx).unwrap();
    a.mov(r8, rax).unwrap();
    a.mov(r9, rdx).unwrap();
    a.mov(rax, (-129i64) as u64).unwrap();
    a.mov(rdx, u64::MAX).unwrap();
    a.mov(r10, 7u64).unwrap();
    a.idiv(r10).unwrap();
    a.test(r8, r8).unwrap();
    a.ret().unwrap();
    recovered(
        a.assemble(BASE + RVA).unwrap(),
        &[[u64::MAX; 16], [0x8000000000000001; 16], [0x100000001; 16]],
    );
}

#[test]
fn private_addresses_cannot_escape_into_native_output() {
    let mut arena = Expressions::default();
    arena.private_range(0x200000000, 0x1000);
    let registers = std::array::from_fn(|n| arena.input(n as u64));
    let flags = arena.input(16);
    let target = arena.constant(0x200000100);
    let blocks = vec![crate::devirt::x64::graph::Block {
        paths: vec![Path {
            conditions: Vec::new(),
            stores: Vec::new(),
            assignments: Vec::new(),
            end: End::Transfer {
                registers,
                flags,
                target,
            },
        }],
    }];
    let function = Function {
        arena: &arena,
        blocks: &blocks,
        slots: 34,
        start: Start::Function(0x1000),
        guest_stack: 0,
    };
    assert!(
        emit(
            &[function],
            BASE,
            RVA,
            &super::super::budget::Budget::new().unwrap()
        )
        .is_err()
    );
}

#[test]
fn recovered_x64_signed_division_uses_both_dividend_halves() {
    for width in [32, 64] {
        let mut a = CodeAssembler::new(64).unwrap();
        if width == 64 {
            a.cqo().unwrap();
            a.idiv(rbx).unwrap();
        } else {
            a.cdq().unwrap();
            a.idiv(ebx).unwrap();
        }
        a.test(rax, rax).unwrap(); // IDIV arithmetic flags are undefined.
        a.ret().unwrap();
        let inputs = [0, 1, 0x80000001, u64::MAX - 128, 0x8000000000000001].map(|value| {
            let mut input = [0xabcdef0123456789; 16];
            input[0] = value;
            input[3] = 7;
            input
        });
        recovered(a.assemble(BASE + RVA).unwrap(), &inputs);
    }
}

#[test]
fn recovered_x64_loads_keep_order_across_guest_stores() {
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(r10, qword_ptr(rdi)).unwrap();
    a.mov(qword_ptr(rdi), r8).unwrap();
    a.mov(rax, qword_ptr(rdi)).unwrap();
    a.mov(qword_ptr(rdi + 8), r10).unwrap();
    a.ret().unwrap();
    let mut input = [0u64; 16];
    input[7] = STACK + 0x1000;
    input[8] = 0x123456789abcdef0;
    recovered(a.assemble(BASE + RVA).unwrap(), &[input]);
}

#[test]
fn native_x64_runtime_data_pointers_rebase_with_dir64_fixups() {
    let mut arena = Expressions::default();
    let mut registers = std::array::from_fn(|n| arena.input(n as u64));
    let old_sp = registers[4];
    let eight = arena.constant(8);
    registers[4] = arena.binary(M::Add, old_sp, eight, 64);
    arena.private_range(0x200000000, 0x10000);
    registers[0] = arena.constant(0x200001234);
    arena.link_runtime_data(0x200000000, 0x4ba000, 0x10000);
    let flags = arena.input(16);
    let target = arena.intern(Expr::Load(old_sp, 64, R::SS, 0));
    let blocks = vec![crate::devirt::x64::graph::Block {
        paths: vec![Path {
            conditions: Vec::new(),
            stores: Vec::new(),
            assignments: Vec::new(),
            end: End::Transfer {
                registers,
                flags,
                target,
            },
        }],
    }];
    let function = Function {
        arena: &arena,
        blocks: &blocks,
        slots: 34,
        start: Start::Function(0x1000),
        guest_stack: 0,
    };
    let program = emit(
        &[function],
        BASE,
        RVA,
        &super::super::budget::Budget::new().unwrap(),
    )
    .unwrap();
    assert!(!program.relocations.is_empty());
    for delta in [0, 0x100000000] {
        let state = execute(&program, delta, [u64::MAX; 16], 0x203);
        assert_eq!(
            state.registers[0].get(),
            Some(BASE + delta + 0x4ba000 + 0x1234)
        );
        assert_eq!(state.registers[4].get(), Some(STACK + 8));
    }
}
