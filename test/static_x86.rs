use super::*;
const BASE: u32 = 0x1000;
const STACK: u32 = 0x20000000;

#[test]
fn setcc_preserves_flags_and_high_bytes_for_all_conditions() {
    for flags in 0..32u32 {
        let (c, p, z, s, o) = (
            flags & 1 != 0,
            flags & 2 != 0,
            flags & 4 != 0,
            flags & 8 != 0,
            flags & 16 != 0,
        );
        let expected = [
            o,
            !o,
            c,
            !c,
            z,
            !z,
            c || z,
            !c && !z,
            s,
            !s,
            p,
            !p,
            s != o,
            s == o,
            z || s != o,
            !z && s == o,
        ];
        for (op, expected) in expected.into_iter().enumerate() {
            let mut image = Image::default();
            image.add(BASE, vec![0x0f, 0x90 + op as u8, 0xc0]).unwrap();
            let mut state = State::new(BASE, STACK);
            state.flags = Value::constant(
                2 | u32::from(c)
                    | (u32::from(p) << 2)
                    | (u32::from(z) << 6)
                    | (u32::from(s) << 7)
                    | (u32::from(o) << 11),
            );
            let before = state.flags;
            state.registers[0] = Value::constant(0x12345678);
            let i = image.instruction(BASE).unwrap();
            execute(&mut state, &image, &i).unwrap();
            assert_eq!(
                state.registers[0].get(),
                Some(0x12345600 | u32::from(expected))
            );
            assert_eq!(state.flags, before);
        }
    }
    let unknown = run(&[0xb8, 0x78, 0x56, 0x34, 0x12, 0x0f, 0x94, 0xc0]).unwrap();
    assert_eq!(
        unknown.registers[0].candidates(),
        Some([0x12345600, 0x12345601])
    );
}
fn run(bytes: &[u8]) -> Result<State> {
    let mut image = Image::default();
    image.add(BASE, bytes.to_vec())?;
    let end = BASE + bytes.len() as u32;
    let mut result: Option<State> = None;
    analyze(&mut image, State::new(BASE, STACK), |image, state| {
        if state.pc == end {
            if let Some(previous) = &mut result {
                previous.join(state, image);
            } else {
                result = Some(state.clone());
            }
            Ok(Action::Finish)
        } else {
            Ok(Action::Decode)
        }
    })?;
    result.context("no final static state")
}
#[test]
fn partial_registers_and_mixed_width_stack_preserve_values() {
    // MOV EAX,12345678; MOV AH,AB; MOV AL,CD; MOVZX ECX,AX;
    // PUSH EAX; PUSH AX; POP CX; POP EDX.
    let s = run(&[
        0xb8, 0x78, 0x56, 0x34, 0x12, 0xb4, 0xab, 0xb0, 0xcd, 0x0f, 0xb7, 0xc8, 0x50, 0x66, 0x50,
        0x66, 0x59, 0x5a,
    ])
    .unwrap();
    assert_eq!(s.registers[0].get(), Some(0x1234abcd));
    assert_eq!(s.registers[1].get(), Some(0xabcd));
    assert_eq!(s.registers[2].get(), Some(0x1234abcd));
    assert_eq!(s.esp().unwrap(), STACK);
}
#[test]
fn carry_survives_increment_and_signed_shift_uses_operand_width() {
    let s = run(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc0, 1, 0x40]).unwrap();
    assert_eq!(s.registers[0].get(), Some(1));
    assert_eq!(s.flags.bit(CF), Some(true));
    assert_eq!(s.flags.bit(ZF), Some(false));
    // SAR AL,CL at count eight sign-extends the byte, keeping upper EAX.
    let s = run(&[0xb8, 0x80, 0, 0, 0x80, 0xb1, 8, 0xd2, 0xf8, 0x0f, 0xc8]).unwrap();
    assert_eq!(s.registers[0].get(), Some(0xff000080));
    assert_eq!(s.flags.bit(SF), Some(true));
    assert_eq!(s.flags.bit(OF), None);
}
#[test]
fn unknown_condition_explores_both_edges_and_joins_conservatively() {
    let mut code = vec![0x74, 7, 0xb8, 7, 0, 0, 0, 0xeb, 5, 0xb8, 7, 0, 0, 0];
    let same = run(&code).unwrap();
    assert_eq!(same.registers[0].get(), Some(7));
    code[10] = 8;
    let different = run(&code).unwrap();
    assert_eq!(different.registers[0].get(), None);
}
#[test]
fn unknown_flags_and_uninitialized_memory_are_not_zero() {
    let s = run(&[0x9c, 0x58]).unwrap();
    assert_eq!(s.registers[0].get(), None);
    let s = run(&[0x8b, 0x04, 0x24]).unwrap();
    assert_eq!(s.registers[0].get(), None);
    assert!(run(&[0x89, 0x01]).is_err()); // MOV [unknown ECX],EAX.
}

#[test]
fn unsigned_multiply_preserves_the_high_word_and_unknown_inputs() {
    // EAX=FFFFFFFF; ECX=2; MUL ECX -> EDX:EAX = 1:FFFFFFFE.
    let s = run(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xb9, 2, 0, 0, 0, 0xf7, 0xe1]).unwrap();
    assert_eq!(s.registers[0].get(), Some(0xfffffffe));
    assert_eq!(s.registers[2].get(), Some(1));
    assert_eq!(s.flags.bit(CF), Some(true));
    assert_eq!(s.flags.bit(ZF), None);
    let unknown = run(&[0xf7, 0xe1]).unwrap();
    assert_eq!(unknown.registers[0].get(), None);
    assert_eq!(unknown.registers[2].get(), None);
    assert_eq!(unknown.flags.bit(CF), None);
}
#[test]
fn saved_register_identities_and_exchange_address_are_preserved() {
    let initial = State::new(BASE, STACK);
    let s = run(&[0x60, 0x61]).unwrap();
    assert_eq!(s.registers, initial.registers);
    let at = STACK + 0x40;
    let mut code = vec![0xb8];
    code.extend(at.to_le_bytes());
    code.extend([0xc7, 0x00, 0x44, 0x33, 0x22, 0x11, 0x87, 0x00]);
    let s = run(&code).unwrap();
    assert_eq!(s.registers[0].get(), Some(0x11223344));
    assert_eq!(s.memory[&at].get(), Some(at));
}
#[test]
fn loops_and_unsupported_control_transfers_fail_instead_of_skipping_paths() {
    assert!(
        run(&[0x74, 0xfe])
            .unwrap_err()
            .to_string()
            .contains("termination proof")
    );
    assert!(run(&[0x66, 0xc3]).is_err());
}

#[test]
fn unaligned_spill_preserves_an_unknown_input_identity() {
    // MOV [ESP+1],EAX; MOV ECX,[ESP+1], across two initially unknown words.
    let s = run(&[0x89, 0x44, 0x24, 1, 0x8b, 0x4c, 0x24, 1]).unwrap();
    assert_eq!(s.registers[1], State::new(BASE, STACK).registers[0]);
}

#[test]
fn shared_callee_keeps_distinct_callers_and_arguments() {
    // EAX=1; CALL INC; EBX=EAX; EAX=2; CALL INC; JMP end; INC EAX; RET.
    let s = run(&[
        0xb8, 1, 0, 0, 0, 0xe8, 14, 0, 0, 0, 0x89, 0xc3, 0xb8, 2, 0, 0, 0, 0xe8, 2, 0, 0, 0, 0xeb,
        2, 0x40, 0xc3,
    ])
    .unwrap();
    assert_eq!(s.registers[3].get(), Some(2));
    assert_eq!(s.registers[0].get(), Some(3));
}

#[test]
fn boolean_product_retains_two_targets_through_private_spills() {
    let target = 0x1234_5678;
    let bit = Value::UNKNOWN.op(Value::constant(1), M::And, 32);
    let product = bit.op(Value::constant(target), M::Imul, 32);
    assert_eq!(product.candidates(), Some([0, target]));
    let image = Image::default();
    let mut state = State::new(BASE, STACK);
    state.push(&image, product).unwrap();
    let loaded = state.pop(&image).unwrap();
    assert_eq!(loaded.candidates(), Some([0, target]));
    assert_eq!(loaded.assume_zero(true).get(), Some(0));
    assert_eq!(loaded.assume_zero(false).get(), Some(target));
    // A partial overwrite must invalidate the old pair, not resurrect it.
    state.write(&image, STACK, 4, product);
    state.write(&image, STACK + 1, 1, Value::constant(0xab));
    assert_eq!(
        state.read(&image, STACK, 4).candidates(),
        Some([0xab00, 0x1234_ab78])
    );
}

#[test]
fn finite_values_overapproximate_arithmetic_joins_and_partial_writes() {
    fn contains(value: Value, n: u32) -> bool {
        (n & value.known) == (value.bits & value.known)
            && value.candidates().is_none_or(|pair| pair.contains(&n))
    }
    let mut random = 0x1020_3040u32;
    for _ in 0..256 {
        let mut next = || {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            random
        };
        let aa = [next(), next()];
        let bb = [next(), next()];
        let a = Value::pair(aa[0], aa[1]);
        let b = Value::pair(bb[0], bb[1]);
        for n in aa.into_iter().chain(bb) {
            assert!(contains(a.join(b), n));
        }
        for width in [8, 16, 32] {
            let mask = Value::mask(width);
            for x in aa {
                for y in bb {
                    for (op, n) in [
                        (M::Add, x.wrapping_add(y)),
                        (M::Sub, x.wrapping_sub(y)),
                        (M::Imul, x.wrapping_mul(y)),
                        (M::And, x & y),
                        (M::Or, x | y),
                        (M::Xor, x ^ y),
                    ] {
                        assert!(contains(a.op(b, op, width), n & mask));
                    }
                }
            }
        }
        for x in aa {
            for y in bb {
                assert!(contains(
                    a.insert(b, 8, 8),
                    (x & !0xff00) | ((y & 255) << 8)
                ));
            }
        }
        for x in aa {
            assert!(contains(a.extract(8, 16), (x >> 8) & 0xffff));
        }
    }
    // Equal nonrelational sets do not prove equal runtime values.
    assert!(contains(
        Value::pair(3, 5).op(Value::pair(3, 5), M::Xor, 32),
        6
    ));
    assert_eq!(
        Value::pair(0, 0x1234).join(Value::UNKNOWN).candidates(),
        None
    );
}
