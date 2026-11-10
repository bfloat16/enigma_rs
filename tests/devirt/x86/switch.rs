#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[test]
fn runtime_native_addresses_do_not_become_bytecode_on_numeric_overlap() {
    for native in [true, false] {
        let mut session = Session::synthetic_program(vec![0x89, 0x07, 0xc3]); // mov [edi], eax; ret
        let mut state = session.initial.clone();
        let pointer = 0x0092e724;
        state.code_ranges.push((pointer - 16, 64, 0x400000));
        let input = session.expressions.input(7);
        let destination = session.expressions.intern(Expr::GuestPointer(input));
        state.registers[7] = destination;
        state.cpu.registers[7] = Value::UNKNOWN;
        let value = if native {
            let base = session.expressions.intern(Expr::ImageBase);
            let offset = session.expressions.constant(pointer - 0x400000);
            session
                .expressions
                .binary(iced_x86::Mnemonic::Add, base, offset, 32)
        } else {
            session.expressions.intern(Expr::PrivateAddress(pointer))
        };
        state.registers[0] = value;
        state.cpu.registers[0] = Value::constant(pointer);
        let instruction = session.image.instruction(0x1000).unwrap();
        state
            .step(&mut session.expressions, &session.image, &instruction)
            .unwrap();
        let stored = state.stores.last().unwrap().value;
        if native {
            assert_eq!(stored, value);
        } else {
            assert_eq!(
                *session.expressions.node(stored),
                Expr::Bytecode(pointer - 0x400000)
            );
        }
    }
}

#[test]
fn runtime_cursor_candidates_survive_cfg_binding_and_a_diamond() {
    use crate::devirt::x86::graph::{Graph, Start};
    use iced_x86::code_asm::*;
    let mut code = CodeAssembler::new(32).unwrap();
    let mut join = code.create_label();
    let mut decode = code.create_label();
    code.and(eax, 1).unwrap();
    code.imul_3(ebx, eax, 0x20000100).unwrap();
    code.push(ebx).unwrap();
    code.test(ecx, ecx).unwrap();
    code.jz(join).unwrap();
    code.nop().unwrap();
    code.set_label(&mut join).unwrap();
    code.pop(ebx).unwrap();
    code.test(ebx, ebx).unwrap();
    code.jz(decode).unwrap();
    code.mov(dword_ptr(ebp), ebx).unwrap();
    code.set_label(&mut decode).unwrap();
    code.ret().unwrap();
    let bytes = code.assemble(0x1000).unwrap();
    let decoder = 0x1000 + bytes.len() as u32 - 1;
    let mut session = Session::synthetic_program(bytes);
    session.decoder = decoder;
    session.guest_layout = Some([0; 9]);
    session.pc_scores.insert(0, 1);
    let frame = session.stack - 0x100;
    let mut state = session.initial.clone();
    state.cpu.registers[5] = Value::constant(frame);
    state.registers[5] = session.expressions.intern(Expr::PrivateAddress(frame));
    let target = session.expressions.constant(0x20000200);
    write(
        &mut session,
        &mut state,
        frame,
        target,
        Value::constant(0x20000200),
    );
    session.initial = state;
    // The decoder refuses UNKNOWN on either edge; no guessed branch is allowed.
    let graph = Graph::recover_session(session, Start::Function(0x1000)).unwrap();
    assert!(graph.blocks.len() < 20);
}

#[test]
fn runtime_nonzero_cursor_write_refines_both_edges_after_a_spill() {
    use iced_x86::code_asm::*;
    for compare in [false, true] {
        let mut code = CodeAssembler::new(32).unwrap();
        let mut skip = code.create_label();
        code.and(eax, 1).unwrap();
        code.imul_3(ebx, eax, 0x12345678).unwrap();
        code.push(ebx).unwrap();
        code.pop(edx).unwrap();
        if compare {
            code.cmp(edx, 0).unwrap();
        } else {
            code.test(edx, edx).unwrap();
        }
        code.jz(skip).unwrap();
        code.mov(dword_ptr(edi), edx).unwrap();
        code.set_label(&mut skip).unwrap();
        code.ret().unwrap();
        let mut session = Session::synthetic_program(code.assemble(0x1000).unwrap());
        let at = session.stack - 0x100;
        let mut state = session.initial.clone();
        state.cpu.registers[7] = Value::constant(at);
        state.registers[7] = session.expressions.intern(Expr::PrivateAddress(at));
        let initial = session.expressions.constant(0x55667788);
        write(
            &mut session,
            &mut state,
            at,
            initial,
            Value::constant(0x55667788),
        );
        let edges = session.advance(state).unwrap();
        assert_eq!(edges.len(), 2);
        let mut results = Vec::new();
        for edge in edges {
            let Boundary::Continue(state) = edge else {
                panic!("missing conditional edge")
            };
            let zero = state.conditions.last().unwrap().taken;
            assert_eq!(
                state.cpu.registers[2].get(),
                Some(if zero { 0 } else { 0x12345678 })
            );
            let mut end = session.advance(state).unwrap();
            let Boundary::Return(state) = end.pop().unwrap() else {
                panic!("did not return")
            };
            results.push(state.cpu.read(&session.image, at, 4).get().unwrap());
        }
        results.sort_unstable();
        assert_eq!(results, [0x12345678, 0x55667788]);
    }
}

fn write(
    session: &mut Session,
    state: &mut StateExpressions,
    at: u32,
    expression: Id,
    numeric: Value,
) {
    state.write(&mut session.expressions, at, 4, expression);
    state.cpu.write(&session.image, at, 4, numeric);
}

fn copy(
    session: &mut Session,
    mut state: StateExpressions,
    source: (Id, Value),
    target: (Id, Value),
    size: u32,
) -> StateExpressions {
    let sp = state.cpu.esp().unwrap();
    let size_id = session.expressions.constant(size);
    for (index, (expression, numeric)) in [source, target, (size_id, Value::constant(size))]
        .into_iter()
        .enumerate()
    {
        write(
            session,
            &mut state,
            sp + 4 + index as u32 * 4,
            expression,
            numeric,
        );
    }
    state.cpu.pc = session.callbacks + 8 * 16;
    let mut boundaries = session.advance(state).unwrap();
    assert_eq!(boundaries.len(), 1);
    let Boundary::Return(state) = boundaries.pop().unwrap() else {
        panic!("copy did not return");
    };
    state
}

#[test]
fn runtime_copy_matches_forward_byte_overlap_in_both_directions() {
    for (src, dst, expected) in [
        (0u32, 1u32, [1u8, 1, 1, 1, 1, 6, 7, 8]),
        (1, 0, [2, 3, 4, 5, 5, 6, 7, 8]),
    ] {
        let mut session = Session::synthetic_program(vec![0xc3]);
        let mut state = session.initial.clone();
        let at = session.stack - 0x100;
        for (offset, value) in [(0, 0x04030201), (4, 0x08070605)] {
            let id = session.expressions.constant(value);
            write(
                &mut session,
                &mut state,
                at + offset,
                id,
                Value::constant(value),
            );
        }
        let source = session.expressions.intern(Expr::PrivateAddress(at + src));
        let target = session.expressions.intern(Expr::PrivateAddress(at + dst));
        let state = copy(
            &mut session,
            state,
            (source, Value::constant(at + src)),
            (target, Value::constant(at + dst)),
            4,
        );
        for (offset, byte) in expected.into_iter().enumerate() {
            assert_eq!(
                state.cpu.read(&session.image, at + offset as u32, 1).get(),
                Some(byte as u32)
            );
            let value = state.read(
                &mut session.expressions,
                &session.image,
                at + offset as u32,
                1,
                source,
            );
            assert_eq!(session.expressions.value(value.unwrap()), Some(byte as u32));
        }
        assert_eq!(
            session.expressions.value(state.registers[0]),
            Some(at + dst)
        );
        assert_eq!(state.cpu.registers[0].get(), Some(at + dst));
        assert_eq!(state.cpu.esp().unwrap(), session.stack + 16);
    }
}

#[test]
fn runtime_copy_returns_symbolic_destination_and_ignores_nonpositive_counts() {
    for size in [0, u32::MAX, 0x80000000] {
        let mut session = Session::synthetic_program(vec![0xc3]);
        let state = session.initial.clone();
        let input = session.expressions.input(0);
        let target = session.expressions.intern(Expr::GuestPointer(input));
        let invalid = session.expressions.input(2);
        let state = copy(
            &mut session,
            state,
            (invalid, Value::UNKNOWN),
            (target, Value::UNKNOWN),
            size,
        );
        assert_eq!(state.registers[0], target);
        assert_eq!(state.cpu.registers[0].get(), None);
        assert!(state.stores.is_empty());
    }
}

#[test]
fn runtime_copy_keeps_guest_writes_and_return_pointer_symbolic() {
    let mut session = Session::synthetic_program(vec![0xc3]);
    let mut state = session.initial.clone();
    let at = session.stack - 0x100;
    let data = session.expressions.constant(0x12345678);
    write(
        &mut session,
        &mut state,
        at,
        data,
        Value::constant(0x12345678),
    );
    let source = session.expressions.intern(Expr::PrivateAddress(at));
    let target = session.expressions.input(1);
    let target = session.expressions.intern(Expr::GuestPointer(target));
    let state = copy(
        &mut session,
        state,
        (source, Value::constant(at)),
        (target, Value::UNKNOWN),
        4,
    );
    assert_eq!(state.registers[0], target);
    assert_eq!(state.stores.len(), 4);
    for (index, store) in state.stores.iter().enumerate() {
        assert_eq!(store.width, 8);
        assert_eq!(store.epoch, index as u32);
        assert_eq!(
            session.expressions.value(store.value),
            Some((0x12345678u32 >> (index * 8)) & 255)
        );
    }
}

#[test]
fn runtime_handler_cache_is_keyed_by_selector() {
    let mut session = Session::synthetic_program(vec![0xc3]);
    session.cursor = 0x20010000;
    session.context = 0x20050000;
    Arc::get_mut(&mut session.profile)
        .unwrap()
        .handlers
        .insert(7, vec![0x90]);
    let state = session.initial.clone();
    let first = session
        .enter_case(state.clone(), 7, session.dispatch)
        .unwrap();
    let again = session
        .enter_case(state.clone(), 7, session.dispatch)
        .unwrap();
    assert_eq!(first.cpu.registers[0], again.cpu.registers[0]);
    assert_eq!(session.compiled.len(), 1);
    assert!(session.enter_case(state, 7, session.dispatch + 4).is_err());
}

#[test]
fn retired_private_spills_are_removed_and_reads_require_reinitialization() {
    let mut session = Session::synthetic_program(vec![0xc3]);
    let mut state = session.initial.clone();
    let top = state.cpu.esp().unwrap();
    let retired = top - 8;
    let value = session.expressions.constant(0x12345678);
    state.write(&mut session.expressions, retired, 4, value);
    state
        .cpu
        .write(&session.image, retired, 4, Value::constant(0x12345678));
    state.retire_stack(&mut session.expressions).unwrap();
    assert!(!state.words.contains_key(&retired));
    assert!(
        !state
            .cpu
            .live_memory(0)
            .iter()
            .any(|(at, _)| *at == retired)
    );
    let pointer = session.expressions.intern(Expr::PrivateAddress(retired));
    assert!(
        state
            .read(
                &mut session.expressions,
                &session.image,
                retired,
                4,
                pointer
            )
            .is_err()
    );
    state.write(&mut session.expressions, retired, 2, value);
    state
        .cpu
        .write(&session.image, retired, 2, Value::constant(0x5678));
    assert!(
        state
            .read(
                &mut session.expressions,
                &session.image,
                retired,
                4,
                pointer
            )
            .is_err()
    );
    let read = state
        .read(
            &mut session.expressions,
            &session.image,
            retired,
            2,
            pointer,
        )
        .unwrap();
    assert_eq!(session.expressions.value(read), Some(0x5678));
}

#[test]
fn overlapping_spills_match_bytes_at_unaligned_and_wrapping_addresses() {
    use std::collections::HashMap;
    for base in [0x20001000u32, 0xfffffff8] {
        let mut session = Session::synthetic_program(vec![0xc3]);
        let mut state = session.initial.clone();
        let mut expected = HashMap::new();
        let mut seed = 0x194a7e31u32;
        for n in 0..256u32 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let at = base.wrapping_add((seed >> 16) & 15);
            let size = [1, 2, 4][n as usize % 3];
            let id = session.expressions.constant(seed);
            state.write(&mut session.expressions, at, size, id);
            state
                .cpu
                .write(&session.image, at, size, Value::constant(seed));
            for offset in 0..size {
                expected.insert(at.wrapping_add(offset), (seed >> (offset * 8)) as u8);
            }
            for offset in 0..16u32 {
                let address = base.wrapping_add(offset);
                for size in [1, 2, 4] {
                    let bytes = (0..size)
                        .map(|n| expected.get(&address.wrapping_add(n)).copied())
                        .collect::<Option<Vec<_>>>();
                    if let Some(bytes) = bytes {
                        let want = bytes
                            .iter()
                            .enumerate()
                            .fold(0u32, |v, (n, b)| v | u32::from(*b) << (n * 8));
                        let pointer = session.expressions.constant(address);
                        let got = state
                            .read(
                                &mut session.expressions,
                                &session.image,
                                address,
                                size,
                                pointer,
                            )
                            .unwrap();
                        assert_eq!(
                            session.expressions.value(got),
                            Some(want),
                            "address={address:#x} size={size}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn retiring_an_unaligned_spill_keeps_its_live_tail() {
    let mut session = Session::synthetic_program(vec![0xc3]);
    let mut state = session.initial.clone();
    let top = state.cpu.esp().unwrap();
    let value = session.expressions.input(0);
    state.write(&mut session.expressions, top - 1, 4, value);
    state.cpu.write(&session.image, top - 1, 4, Value::input(1));
    state.retire_stack(&mut session.expressions).unwrap();
    let pointer = session.expressions.intern(Expr::PrivateAddress(top));
    let got = state
        .read(&mut session.expressions, &session.image, top, 2, pointer)
        .unwrap();
    assert_eq!(
        session.expressions.extract(got, 0, 8),
        session.expressions.extract(value, 8, 8)
    );
    assert_eq!(
        session.expressions.extract(got, 8, 8),
        session.expressions.extract(value, 16, 8)
    );
    let retired = session.expressions.intern(Expr::PrivateAddress(top - 1));
    assert!(
        state
            .read(
                &mut session.expressions,
                &session.image,
                top - 1,
                1,
                retired
            )
            .is_err()
    );
}
