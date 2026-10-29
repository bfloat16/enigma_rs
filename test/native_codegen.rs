use super::{
    End, Expr, Expressions, Function, Id, M, Path, Program, R, Start, emit, put_u32_at, verify,
};
use crate::devirt::{
    graph::Block,
    lift::{Predicate, Store},
    static_x86::{self, Image, State, Value},
};

const BASE: u32 = 0x400000;
const RVA: u32 = 0x10000;
const STACK: u32 = 0x20080000;
const STOP: u32 = 0x30000000;
fn inputs(a: &mut Expressions) -> [Id; 8] {
    std::array::from_fn(|r| a.input(r as u32))
}
fn returning(a: &mut Expressions, mut registers: [Id; 8]) -> End {
    let sp = a.input(4);
    let four = a.constant(4);
    registers[4] = a.binary(M::Add, sp, four, 32);
    let target = a.intern(Expr::Load(sp, 32, R::SS, 0));
    let flags = a.input(8);
    End::Transfer {
        registers,
        flags,
        target,
    }
}
fn path(end: End) -> Path {
    Path {
        conditions: Vec::new(),
        stores: Vec::new(),
        assignments: Vec::new(),
        end,
    }
}
fn function<'a>(a: &'a Expressions, b: &'a [Block], start: Start) -> Function<'a> {
    Function {
        arena: a,
        blocks: b,
        slots: 24,
        start,
        guest_stack: 128,
    }
}
fn execute(
    program: &Program,
    delta: u32,
    registers: [u32; 8],
    flags: u32,
    memory: &[(u32, u32)],
    extra: &[(u32, Vec<u8>)],
) -> State {
    let mut bytes = program.bytes.clone();
    for &site in &program.relocations {
        let at = (site - RVA) as usize;
        let v = crate::common::io::u32_at(&bytes, at).unwrap();
        put_u32_at(&mut bytes, at, v.wrapping_add(delta)).unwrap();
    }
    let mut image = Image::default();
    image.add(BASE + delta + RVA, bytes).unwrap();
    image.zero(STACK - 0x40000, 0x80000);
    for &(address, ref bytes) in extra {
        image.add(address, bytes.clone()).unwrap();
    }
    let mut state = State::new(
        BASE + delta + program.entries[&Start::Function(0x1000)],
        STACK,
    );
    state.registers = registers.map(Value::constant);
    state.registers[4] = Value::constant(STACK);
    state.flags = Value::constant(flags);
    state.write(&image, STACK, 4, Value::constant(STOP));
    for &(at, v) in memory {
        state.write(&image, at, 4, Value::constant(v));
    }
    for _ in 0..100000 {
        if state.pc == STOP {
            return state;
        }
        let instruction = image.instruction(state.pc).unwrap();
        assert!(
            static_x86::execute(&mut state, &image, &instruction)
                .unwrap()
                .is_none(),
            "synthetic code took an unknown branch"
        );
    }
    panic!("synthetic native code failed to terminate")
}
#[test]
fn direct_emission_preserves_narrow_signed_shifts_and_partial_registers() {
    let mut a = Expressions::default();
    let mut regs = inputs(&mut a);
    let byte = a.extract(regs[0], 0, 8);
    let n = a.constant(9);
    let signed = a.binary(M::Sar, byte, n, 8);
    regs[0] = a.insert(regs[0], signed, 0, 8);
    let word = a.extract(regs[1], 0, 16);
    regs[1] = a.intern(Expr::Unary(M::Movsx, word, 16));
    let b = vec![Block {
        paths: vec![path(returning(&mut a, regs))],
    }];
    let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
    let s = execute(
        &p,
        0,
        [0x12345680, 0xabcd8001, 2, 3, 0, 5, 6, 7],
        0x202,
        &[],
        &[],
    );
    assert_eq!(s.registers[0].get(), Some(0x123456ff));
    assert_eq!(s.registers[1].get(), Some(0xffff8001));
    assert_eq!(s.esp().unwrap(), STACK + 4);
    assert_eq!(s.flags.get(), Some(0x202));
}
#[test]
fn parallel_copies_and_loop_edges_keep_old_values() {
    let mut a = Expressions::default();
    let mut regs = inputs(&mut a);
    let x = a.intern(Expr::Cell(18));
    let y = a.intern(Expr::Cell(19));
    let mut first = path(End::Next(1));
    first.assignments = vec![(18, regs[0]), (19, regs[1])];
    let mut swap = path(End::Next(2));
    swap.assignments = vec![(18, y), (19, x)];
    regs[0] = x;
    regs[1] = y;
    let b = vec![
        Block { paths: vec![first] },
        Block { paths: vec![swap] },
        Block {
            paths: vec![path(returning(&mut a, regs))],
        },
    ];
    let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
    let s = execute(&p, 0, [11, 22, 2, 3, 0, 5, 6, 7], 0x202, &[], &[]);
    assert_eq!(s.registers[0].get(), Some(22));
    assert_eq!(s.registers[1].get(), Some(11));
    let mut a = Expressions::default();
    let mut regs = inputs(&mut a);
    let count = a.intern(Expr::Cell(18));
    let sum = a.intern(Expr::Cell(19));
    let zero = a.constant(0);
    let three = a.constant(3);
    let one = a.constant(1);
    let mut init = path(End::Next(1));
    init.assignments = vec![(18, three), (19, zero)];
    let flags = a.flags(M::Cmp, count, zero, zero, 32);
    regs[0] = sum;
    let mut yes = path(returning(&mut a, regs));
    yes.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: true,
        epoch: 0,
    });
    let mut no = path(End::Next(2));
    no.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: false,
        epoch: 0,
    });
    let dec = a.binary(M::Sub, count, one, 32);
    let inc = a.binary(M::Add, sum, one, 32);
    let mut body = path(End::Next(1));
    body.assignments = vec![(18, dec), (19, inc)];
    let b = vec![
        Block { paths: vec![init] },
        Block {
            paths: vec![yes, no],
        },
        Block { paths: vec![body] },
    ];
    let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
    assert_eq!(
        execute(&p, 0, [0; 8], 0x202, &[], &[]).registers[0].get(),
        Some(3)
    );
}
#[test]
fn memory_epochs_preserve_load_before_store_and_load_after_store() {
    let mut a = Expressions::default();
    let mut regs = inputs(&mut a);
    let address = regs[1];
    regs[0] = a.intern(Expr::Load(address, 32, R::DS, 0));
    regs[2] = a.intern(Expr::Load(address, 32, R::DS, 1));
    let five = a.constant(5);
    let mut p = path(returning(&mut a, regs));
    p.stores.push(Store {
        address,
        value: five,
        width: 32,
        segment: R::DS,
        epoch: 0,
    });
    let b = vec![Block { paths: vec![p] }];
    let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
    let s = execute(
        &p,
        0,
        [0, 0x21000000, 0, 3, 0, 5, 6, 7],
        0x202,
        &[(0x21000000, 17)],
        &[],
    );
    assert_eq!(s.registers[0].get(), Some(17));
    assert_eq!(s.registers[2].get(), Some(5));
}
#[test]
fn conditional_load_is_not_speculated_onto_the_other_path() {
    let mut a = Expressions::default();
    let regs = inputs(&mut a);
    let flags = a.input(8);
    let bad = a.constant(0xdead0000);
    let mut r = regs;
    r[0] = a.intern(Expr::Load(bad, 32, R::DS, 0));
    let mut yes = path(returning(&mut a, r));
    yes.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: true,
        epoch: 0,
    });
    let mut r = regs;
    r[0] = a.constant(42);
    let mut no = path(returning(&mut a, r));
    no.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: false,
        epoch: 0,
    });
    let b = vec![Block {
        paths: vec![yes, no],
    }];
    let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
    assert_eq!(
        execute(&p, 0, [0; 8], 0x202, &[], &[]).registers[0].get(),
        Some(42)
    );
}
#[test]
fn native_flags_obey_operand_width_and_preserve_carry_for_increment() {
    for width in [8, 16, 32] {
        let mut a = Expressions::default();
        let regs = inputs(&mut a);
        let x = a.extract(regs[0], 0, width);
        let one = a.constant(1);
        let old = a.input(8);
        let f = a.flags(M::Add, x, one, old, width);
        let mut end = returning(&mut a, regs);
        if let End::Transfer { flags, .. } = &mut end {
            *flags = f;
        }
        let b = vec![Block {
            paths: vec![path(end)],
        }];
        let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
        let value = if width == 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        };
        let s = execute(&p, 0, [value, 1, 2, 3, 0, 5, 6, 7], 0x202, &[], &[]);
        assert_eq!(s.flags.bits & 0x8d5, 0x55);
    }
    let mut a = Expressions::default();
    let regs = inputs(&mut a);
    let old = a.input(8);
    let zero = a.constant(0);
    let f = a.flags(M::Inc, regs[0], zero, old, 32);
    let mut end = returning(&mut a, regs);
    if let End::Transfer { flags, .. } = &mut end {
        *flags = f;
    }
    let b = vec![Block {
        paths: vec![path(end)],
    }];
    let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
    assert_eq!(
        execute(&p, 0, [7, 1, 2, 3, 0, 5, 6, 7], 0x203, &[], &[])
            .flags
            .bits
            & 1,
        1
    );
}
#[test]
fn continuation_symbols_survive_rebasing_and_native_calls() {
    let mut a = Expressions::default();
    let mut regs = inputs(&mut a);
    let four = a.constant(4);
    let sp = a.binary(M::Sub, regs[4], four, 32);
    let continuation = Start::Continuation(0x1234);
    let target = a.intern(Expr::Continuation(0x1234));
    let host = a.intern(Expr::Function(0x2000));
    let flags = a.input(8);
    regs[4] = sp;
    let mut first = path(End::Transfer {
        registers: regs,
        flags,
        target: host,
    });
    first.stores.push(Store {
        address: sp,
        value: target,
        width: 32,
        segment: R::SS,
        epoch: 0,
    });
    let b1 = vec![Block { paths: vec![first] }];
    let mut regs = inputs(&mut a);
    let five = a.constant(5);
    regs[0] = a.binary(M::Add, regs[0], five, 32);
    let b2 = vec![Block {
        paths: vec![path(returning(&mut a, regs))],
    }];
    let p = emit(
        &[
            function(&a, &b1, Start::Function(0x1000)),
            function(&a, &b2, continuation),
        ],
        BASE,
        RVA,
    )
    .unwrap();
    assert!(p.relocations.len() >= 2);
    for delta in [0, 0x100000] {
        let s = execute(
            &p,
            delta,
            [7, 1, 2, 3, 0, 5, 6, 7],
            0x203,
            &[],
            &[(BASE + delta + 0x2000, vec![0x40, 0xc3])],
        );
        assert_eq!(s.registers[0].get(), Some(13));
        assert_eq!(s.esp().unwrap(), STACK + 4);
        assert_eq!(s.registers[5].get(), Some(5));
    }
}
#[test]
fn unresolved_vm_values_and_missing_successors_are_rejected() {
    let mut a = Expressions::default();
    let mut regs = inputs(&mut a);
    regs[0] = a.input(65538);
    let b = vec![Block {
        paths: vec![path(returning(&mut a, regs))],
    }];
    assert!(
        emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA)
            .unwrap_err()
            .to_string()
            .contains("emit")
    );
    assert!(verify(&[0xe9, 0xfc, 0xff, 0xff, 0xff], BASE).is_err());
    let mut a = Expressions::default();
    let regs = inputs(&mut a);
    let flags = a.input(8);
    let mut only = path(returning(&mut a, regs));
    only.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: true,
        epoch: 0,
    });
    let b = vec![Block { paths: vec![only] }];
    assert!(emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).is_err());
}

#[test]
fn native_alu_values_cover_all_widths_and_masked_shift_counts() {
    for width in [8, 16, 32] {
        for op in [
            M::Add,
            M::Sub,
            M::And,
            M::Or,
            M::Xor,
            M::Imul,
            M::Shl,
            M::Shr,
            M::Sar,
            M::Rol,
            M::Ror,
        ] {
            let mut a = Expressions::default();
            let mut regs = inputs(&mut a);
            let lhs = a.extract(regs[0], 0, width);
            let rhs = a.extract(regs[1], 0, width);
            regs[0] = a.binary(op, lhs, rhs, width);
            let b = vec![Block {
                paths: vec![path(returning(&mut a, regs))],
            }];
            let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
            let mask = if width == 32 {
                u32::MAX
            } else {
                (1u32 << width) - 1
            };
            let left = 0x87658183 & mask;
            for count in [0u32, 1, 7, 8, 15, 16, 31, 32, 255] {
                let n = count & 31;
                let right = count & mask;
                let rotate = n % width;
                let expected = match op {
                    M::Add => left.wrapping_add(right),
                    M::Sub => left.wrapping_sub(right),
                    M::And => left & right,
                    M::Or => left | right,
                    M::Xor => left ^ right,
                    M::Imul => left.wrapping_mul(right),
                    M::Shl => left.wrapping_shl(n),
                    M::Shr => left >> n,
                    M::Sar => (((left << (32 - width)) as i32 >> (32 - width)) >> n) as u32,
                    M::Rol if rotate != 0 => (left << rotate) | (left >> (width - rotate)),
                    M::Ror if rotate != 0 => (left >> rotate) | (left << (width - rotate)),
                    M::Rol | M::Ror => left,
                    _ => unreachable!(),
                } & mask;
                let state = execute(
                    &p,
                    0,
                    [0x87658183, count, 2, 3, 0, 5, 6, 7],
                    0x203,
                    &[],
                    &[],
                );
                assert_eq!(
                    state.registers[0].get(),
                    Some(expected),
                    "{op:?} width={width} count={count}"
                );
            }
        }
    }
}

#[test]
fn runtime_zero_shift_preserves_all_guest_flags() {
    let mut a = Expressions::default();
    let regs = inputs(&mut a);
    let old = a.input(8);
    let flags = a.flags(M::Sar, regs[0], regs[1], old, 32);
    let mut end = returning(&mut a, regs);
    if let End::Transfer { flags: f, .. } = &mut end {
        *f = flags;
    }
    let b = vec![Block {
        paths: vec![path(end)],
    }];
    let p = emit(&[function(&a, &b, Start::Function(0x1000))], BASE, RVA).unwrap();
    for count in [0, 32, 64] {
        let state = execute(
            &p,
            0,
            [0x80000001, count, 2, 3, 0, 5, 6, 7],
            0x2d7,
            &[],
            &[],
        );
        assert_eq!(state.flags.get(), Some(0x2d7));
    }
}

fn check_recovered_program(bytes: Vec<u8>, inputs: &[[u32; 8]]) {
    use crate::devirt::{graph::Graph, optimize, switch::Session};
    let session = Session::synthetic_program(bytes.clone());
    let mut graph = Graph::recover_session(session, Start::Function(0x1000)).unwrap();
    assert!(graph.blocks.len() < 200, "recovery unrolled the guest loop");
    optimize::run(&mut graph).unwrap();
    let native = emit(&[Function::from(&graph)], BASE, RVA).unwrap();
    let original = Program {
        bytes,
        entries: [(Start::Function(0x1000), RVA)].into_iter().collect(),
        relocations: Vec::new(),
    };
    for &input in inputs {
        let before = execute(&original, 0, input, 0x203, &[], &[]);
        let after = execute(&native, 0, input, 0x203, &[], &[]);
        assert_eq!(
            before.registers.map(Value::get),
            after.registers.map(Value::get),
            "input={input:x?}"
        );
        assert_eq!(before.flags.get(), after.flags.get(), "input={input:x?}");
    }
}

#[test]
fn recovered_unsigned_product_preserves_high_word_and_defined_flags() {
    use iced_x86::code_asm::*;
    let mut code = CodeAssembler::new(32).unwrap();
    code.mul(ecx).unwrap();
    code.pushfd().unwrap();
    code.pop(ebx).unwrap();
    code.and(ebx, 0x801).unwrap();
    code.push(0x203).unwrap();
    code.popfd().unwrap();
    code.ret().unwrap();
    let mut inputs = Vec::new();
    for a in [0, 1, 0xffff, 0x10000, 0x80000000, 0xffffffff, 0x87654321] {
        for b in [0, 1, 0x10001, 0x80000000, 0xffffffff, 0xfedcba98] {
            inputs.push([a, b, 0x12345678, 3, 0, 5, 6, 7]);
        }
    }
    check_recovered_program(code.assemble(0x1000).unwrap(), &inputs);
}

#[test]
fn recovered_join_preserves_constants_from_both_predecessors() {
    use iced_x86::code_asm::*;
    let mut code = CodeAssembler::new(32).unwrap();
    let mut yes = code.create_label();
    let mut join = code.create_label();
    let mut output = code.create_label();
    code.test(eax, eax).unwrap();
    code.jz(yes).unwrap();
    code.mov(ebx, 11u32).unwrap();
    code.jmp(join).unwrap();
    code.set_label(&mut yes).unwrap();
    code.mov(ebx, 22u32).unwrap();
    code.set_label(&mut join).unwrap();
    code.test(ecx, ecx).unwrap();
    code.jz(output).unwrap();
    code.inc(ebx).unwrap();
    code.set_label(&mut output).unwrap();
    code.mov(eax, ebx).unwrap();
    code.ret().unwrap();
    check_recovered_program(
        code.assemble(0x1000).unwrap(),
        &[
            [0, 0, 2, 3, 0, 5, 6, 7],
            [1, 0, 2, 3, 0, 5, 6, 7],
            [0, 1, 2, 3, 0, 5, 6, 7],
            [1, 1, 2, 3, 0, 5, 6, 7],
        ],
    );
}

#[test]
fn recovered_dead_flag_restores_match_original_x86_on_both_paths() {
    use iced_x86::code_asm::*;
    let mut code = CodeAssembler::new(32).unwrap();
    let mut restore = code.create_label();
    let mut join = code.create_label();
    code.pushfd().unwrap();
    code.pop(ebx).unwrap();
    code.and(ebx, !0x8d5i32).unwrap();
    code.pushfd().unwrap();
    code.push(ebx).unwrap();
    code.test(edx, edx).unwrap();
    code.jz(restore).unwrap();
    code.and(dword_ptr(esp), !0x8d5i32).unwrap();
    code.jmp(join).unwrap();
    code.set_label(&mut restore).unwrap();
    code.mov(dword_ptr(esp), ebx).unwrap();
    code.set_label(&mut join).unwrap();
    code.pop(eax).unwrap();
    code.popfd().unwrap();
    code.ret().unwrap();
    check_recovered_program(
        code.assemble(0x1000).unwrap(),
        &[
            [0, 1, 0, 3, 0, 5, 6, 7],
            [u32::MAX, 1, 1, 3, 0, 5, 6, 7],
            [0x12345678, 1, u32::MAX, 3, 0, 5, 6, 7],
        ],
    );
}

#[test]
fn recovered_loop_converges_and_preserves_narrow_private_memory() {
    use iced_x86::code_asm::*;
    let mut code = CodeAssembler::new(32).unwrap();
    let mut body = code.create_label();
    let mut output = code.create_label();
    code.sub(esp, 4).unwrap();
    code.mov(dword_ptr(esp), 0x12340000u32).unwrap();
    code.set_label(&mut body).unwrap();
    code.inc(byte_ptr(esp)).unwrap();
    code.test(ecx, ecx).unwrap();
    code.jz(output).unwrap();
    code.cmp(byte_ptr(esp), 100).unwrap();
    code.jb(body).unwrap();
    code.set_label(&mut output).unwrap();
    code.mov(eax, dword_ptr(esp)).unwrap();
    code.add(esp, 4).unwrap();
    code.ret().unwrap();
    check_recovered_program(
        code.assemble(0x1000).unwrap(),
        &[[7, 0, 2, 3, 0, 5, 6, 7], [7, 1, 2, 3, 0, 5, 6, 7]],
    );
}

#[test]
fn recovered_unaligned_spill_keeps_parallel_word_bindings() {
    use iced_x86::code_asm::*;
    let mut code = CodeAssembler::new(32).unwrap();
    let mut skip = code.create_label();
    let mut output = code.create_label();
    code.sub(esp, 8).unwrap();
    code.mov(dword_ptr(esp), 0u32).unwrap();
    code.mov(dword_ptr(esp + 4), 0u32).unwrap();
    code.mov(dword_ptr(esp + 1), 0x12345678u32).unwrap();
    code.test(eax, eax).unwrap();
    code.jz(skip).unwrap();
    code.inc(byte_ptr(esp + 2)).unwrap();
    code.set_label(&mut skip).unwrap();
    code.test(ecx, ecx).unwrap();
    code.jz(output).unwrap();
    code.xor(byte_ptr(esp + 4), 0x7f).unwrap();
    code.set_label(&mut output).unwrap();
    code.mov(edx, dword_ptr(esp + 1)).unwrap();
    code.add(esp, 8).unwrap();
    code.ret().unwrap();
    check_recovered_program(
        code.assemble(0x1000).unwrap(),
        &[
            [0, 0, 2, 3, 0, 5, 6, 7],
            [1, 0, 2, 3, 0, 5, 6, 7],
            [0, 1, 2, 3, 0, 5, 6, 7],
            [1, 1, 2, 3, 0, 5, 6, 7],
        ],
    );
}

#[test]
fn recovery_rejects_an_internal_loop_instead_of_dropping_the_path() {
    use crate::devirt::{graph::Graph, switch::Session};
    let result = Graph::recover_session(
        Session::synthetic_program(vec![0xeb, 0xfe]),
        Start::Function(0x1000),
    );
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("internal loop repeats")
    );
}

#[test]
#[ignore = "requires ENIGMA_SAMPLE, ENIGMA_COOKIE_RVA and ENIGMA_CRT_RVA from independent analysis"]
fn sample_native_entry_matches_declared_entry_contract() {
    use crate::{
        common::{
            io::{take, u32_at},
            pe::Pe,
        },
        devirt::native,
        unpack::{config, imports},
    };
    let bytes =
        std::fs::read(std::env::var_os("ENIGMA_SAMPLE").expect("set ENIGMA_SAMPLE")).unwrap();
    let pe = Pe::parse(&bytes).unwrap();
    let base: u32 = pe.image_base.try_into().unwrap();
    let config = config::parse(&pe).unwrap();
    let loader = config.loader.as_ref().unwrap();
    let entry = u32_at(
        config.ctx.as_ref().unwrap(),
        config.layout.unwrap().entry + 4,
    )
    .unwrap()
        - 5;
    // Targets are supplied by the caller's independent analysis, not inferred
    // by a second copy of the implementation under test.
    let target = |name| {
        u32::from_str_radix(
            &std::env::var(name).expect("set ENIGMA_COOKIE_RVA and ENIGMA_CRT_RVA (hex)"),
            16,
        )
        .unwrap()
    };
    let cookie_rva = target("ENIGMA_COOKIE_RVA");
    let crt_rva = target("ENIGMA_CRT_RVA");
    let mut reference = vec![0xe8];
    reference.extend(cookie_rva.wrapping_sub(entry + 5).to_le_bytes());
    reference.push(0xe9);
    reference.extend(crt_rva.wrapping_sub(entry + 10).to_le_bytes());
    let engine = imports::engine_section(&pe, loader).unwrap();
    let host_end = pe
        .sections
        .iter()
        .filter(|s| s.rva < engine.rva)
        .map(|s| s.rva + s.virtual_size.max(s.raw_size))
        .max()
        .unwrap();
    let rva = host_end.div_ceil(0x1000) * 0x1000;
    let mut payload = Vec::new();
    let output = native::append(
        loader,
        take(pe.data, 0, pe.headers_size as usize).unwrap(),
        entry,
        host_end,
        base,
        rva,
        &mut payload,
    )
    .unwrap();
    let patch = output.patches.iter().find(|p| p.rva == entry).unwrap();
    let mut generated = Image::default();
    generated.add(base + rva, payload).unwrap();
    generated.add(base + entry, patch.bytes.clone()).unwrap();
    let mut original = Image::default();
    original.add(base + entry, reference).unwrap();
    fn run(
        image: &mut Image,
        entry: u32,
        cookie: u32,
        crt: u32,
        input: [u32; 8],
        flags: u32,
    ) -> State {
        image.zero(STACK - 0x40000, 0x80000);
        let mut state = State::new(entry, STACK);
        state.registers = input.map(Value::constant);
        state.registers[4] = Value::constant(STACK);
        state.flags = Value::constant(flags);
        let mut calls = 0;
        for _ in 0..100000 {
            if state.pc == crt {
                assert_eq!(calls, 1);
                return state;
            }
            if state.pc == cookie {
                calls += 1;
                assert_eq!(state.esp().unwrap(), STACK - 4);
                state.registers[0] = Value::constant(0x13579bdf);
                state.registers[1] = Value::constant(0x2468ace0);
                state.registers[2] = Value::constant(0xdeadbeef);
                state.flags = Value::constant(0x293);
                state.return_from(image, 0).unwrap();
                continue;
            }
            let instruction = image.instruction(state.pc).unwrap();
            assert!(
                static_x86::execute(&mut state, image, &instruction)
                    .unwrap()
                    .is_none()
            );
        }
        panic!("sample native entry failed to reach CRT");
    }
    for flags in [0x202, 0x203, 0xad7] {
        for input in [
            [0; 8],
            [0xffffffff; 8],
            [
                0x10203040, 0x50607080, 0x12345678, 0x87654321, 0, 0x9abcdef0, 0x11111111,
                0xeeeeeeee,
            ],
        ] {
            let a = run(
                &mut original,
                base + entry,
                base + cookie_rva,
                base + crt_rva,
                input,
                flags,
            );
            let b = run(
                &mut generated,
                base + entry,
                base + cookie_rva,
                base + crt_rva,
                input,
                flags,
            );
            assert_eq!(a.registers.map(Value::get), b.registers.map(Value::get));
            assert_eq!(a.flags.get(), b.flags.get());
        }
    }
}
