use super::*;
use crate::devirt::{
    graph::{Block, Start},
    lift::{Predicate, Store},
    switch::Session,
};
fn path(end: End) -> Path {
    Path {
        conditions: Vec::new(),
        stores: Vec::new(),
        assignments: Vec::new(),
        end,
    }
}
fn exit(arena: &mut Expressions) -> End {
    let mut registers = std::array::from_fn(|r| arena.input(r as u32));
    registers[0] = arena.constant(7);
    let flags = arena.input(8);
    let target = arena.constant(0x30000000);
    End::Transfer {
        registers,
        flags,
        target,
    }
}

#[test]
fn masked_identity_and_redundant_restore_do_not_keep_opaque_branches_alive() {
    let mut arena = Expressions::default();
    let input = arena.input(8);
    let cell = arena.intern(Expr::Cell(17));
    let keep = arena.constant(!0x8d5);
    let saved = arena.binary(M::And, input, keep, 32);
    let identity = arena.binary(M::And, cell, keep, 32);
    let unknown = arena.fresh_input();
    let mut entry = path(End::Next(1));
    entry.assignments.push((17, saved));
    let mut yes = path(End::Next(2));
    yes.conditions.push(Predicate {
        flags: unknown,
        op: M::Je,
        taken: true,
        epoch: 0,
    });
    let mut no = path(End::Next(3));
    no.conditions.push(Predicate {
        flags: unknown,
        op: M::Je,
        taken: false,
        epoch: 0,
    });
    let mut masked = path(End::Next(4));
    masked.assignments.push((17, identity));
    let mut restore = path(End::Next(4));
    restore.assignments.push((17, saved));
    let mut end = exit(&mut arena);
    let End::Transfer { flags, .. } = &mut end else {
        unreachable!()
    };
    *flags = identity;
    let mut graph = Graph {
        session: Session::synthetic(arena),
        blocks: vec![
            Block { paths: vec![entry] },
            Block {
                paths: vec![yes, no],
            },
            Block {
                paths: vec![masked],
            },
            Block {
                paths: vec![restore],
            },
            Block {
                paths: vec![path(end)],
            },
        ],
        slots: 24,
        start: Start::Function(0x1000),
    };
    run(&mut graph).unwrap();
    assert!(
        graph
            .blocks
            .iter()
            .flat_map(|b| &b.paths)
            .all(|p| p.conditions.is_empty())
    );
    let before = graph.blocks.clone();
    run(&mut graph).unwrap();
    assert!(
        graph.blocks == before,
        "optimizer did not reach a fixed point"
    );
    crate::devirt::codegen::emit(
        &[crate::devirt::codegen::Function::from(&graph)],
        0x400000,
        0x10000,
    )
    .unwrap();
}

#[test]
fn flags_bit_liveness_drops_only_overwritten_callback_bits_at_a_join() {
    for observed in [!0x8d5u32, 0x40] {
        let mut arena = Expressions::default();
        let input = arena.input(8);
        let cell = arena.intern(Expr::Cell(17));
        let keep = arena.constant(!0x8d5);
        let preserved = arena.binary(M::And, input, keep, 32);
        let clobber = arena.constant(0x8d5);
        let mut arms = Vec::new();
        for _ in 0..2 {
            let unknown = arena.fresh_input();
            let written = arena.binary(M::And, unknown, clobber, 32);
            let value = arena.binary(M::Or, preserved, written, 32);
            let mut edge = path(End::Next(3));
            edge.assignments.push((17, value));
            arms.push(Block { paths: vec![edge] });
        }
        let mut yes = path(End::Next(1));
        yes.conditions.push(Predicate {
            flags: input,
            op: M::Je,
            taken: true,
            epoch: 0,
        });
        let mut no = path(End::Next(2));
        no.conditions.push(Predicate {
            flags: input,
            op: M::Je,
            taken: false,
            epoch: 0,
        });
        let observed = arena.constant(observed);
        let flags = arena.binary(M::And, cell, observed, 32);
        let mut end = exit(&mut arena);
        let End::Transfer { flags: output, .. } = &mut end else {
            unreachable!()
        };
        *output = flags;
        let mut blocks = vec![Block {
            paths: vec![yes, no],
        }];
        blocks.extend(arms);
        blocks.push(Block {
            paths: vec![path(end)],
        });
        let mut graph = Graph {
            session: Session::synthetic(arena),
            blocks,
            slots: 24,
            start: Start::Function(0x1000),
        };
        run(&mut graph).unwrap();
        let result = crate::devirt::codegen::emit(
            &[crate::devirt::codegen::Function::from(&graph)],
            0x400000,
            0x10000,
        );
        assert_eq!(
            result.is_ok(),
            graph.session.expressions.value(observed) == Some(!0x8d5)
        );
    }
}
#[test]
fn dead_private_branch_with_different_path_lengths_disappears() {
    let mut arena = Expressions::default();
    let flags = arena.input(65538);
    let mut yes = path(End::Next(1));
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
    let end = exit(&mut arena);
    let blocks = vec![
        Block {
            paths: vec![yes, no],
        },
        Block {
            paths: vec![path(End::Next(3))],
        },
        Block {
            paths: vec![path(End::Next(4))],
        },
        Block {
            paths: vec![path(End::Next(4))],
        },
        Block {
            paths: vec![path(end)],
        },
    ];
    let mut graph = Graph {
        session: Session::synthetic(arena),
        blocks,
        slots: 24,
        start: Start::Function(0x1000),
    };
    run(&mut graph).unwrap();
    assert!(
        graph
            .blocks
            .iter()
            .flat_map(|b| &b.paths)
            .all(|p| p.conditions.is_empty())
    );
    assert_eq!(graph.blocks.len(), 2);
    crate::devirt::codegen::emit(
        &[crate::devirt::codegen::Function::from(&graph)],
        0x400000,
        0x10000,
    )
    .unwrap();
}
#[test]
fn guest_stores_prevent_merging_distinct_branches() {
    let mut arena = Expressions::default();
    let flags = arena.input(8);
    let address = arena.input(1);
    let one = arena.constant(1);
    let two = arena.constant(2);
    let end = exit(&mut arena);
    let mut yes = path(End::Next(1));
    yes.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: true,
        epoch: 0,
    });
    yes.stores.push(Store {
        address,
        value: one,
        width: 32,
        segment: iced_x86::Register::DS,
        epoch: 0,
    });
    let mut no = path(End::Next(1));
    no.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: false,
        epoch: 0,
    });
    no.stores.push(Store {
        address,
        value: two,
        width: 32,
        segment: iced_x86::Register::DS,
        epoch: 0,
    });
    let mut graph = Graph {
        session: Session::synthetic(arena),
        blocks: vec![
            Block {
                paths: vec![yes, no],
            },
            Block {
                paths: vec![path(end)],
            },
        ],
        slots: 24,
        start: Start::Function(0x1000),
    };
    run(&mut graph).unwrap();
    assert_eq!(graph.blocks[0].paths.len(), 2);
    assert!(
        graph.blocks[0]
            .paths
            .iter()
            .all(|p| p.stores.len() == 1 && !p.conditions.is_empty())
    );
}
#[test]
fn join_does_not_assume_one_predecessors_constant() {
    let mut arena = Expressions::default();
    let flags = arena.input(8);
    let one = arena.constant(1);
    let two = arena.constant(2);
    let value = arena.intern(Expr::Cell(18));
    let mut yes = path(End::Next(1));
    yes.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: true,
        epoch: 0,
    });
    yes.assignments.push((18, one));
    let mut no = path(End::Next(1));
    no.conditions.push(Predicate {
        flags,
        op: M::Je,
        taken: false,
        epoch: 0,
    });
    no.assignments.push((18, two));
    let mut end = exit(&mut arena);
    if let End::Transfer { registers, .. } = &mut end {
        registers[0] = value;
    }
    let mut graph = Graph {
        session: Session::synthetic(arena),
        blocks: vec![
            Block {
                paths: vec![yes, no],
            },
            Block {
                paths: vec![path(end)],
            },
        ],
        slots: 24,
        start: Start::Function(0x1000),
    };
    run(&mut graph).unwrap();
    let End::Transfer { registers, .. } = &graph.blocks[1].paths[0].end else {
        panic!("lost return")
    };
    assert_eq!(registers[0], value);
}

#[test]
fn predecessor_partition_matches_full_refinement_on_cycles_and_branches() {
    let mut seed = 17u32;
    for count in 2..50usize {
        let mut arena = Expressions::default();
        let terminal = exit(&mut arena);
        let mut blocks = Vec::new();
        for index in 0..count {
            let mut paths = Vec::new();
            for _ in 0..1 + index % 3 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                paths.push(path(if seed.is_multiple_of(7) {
                    terminal.clone()
                } else {
                    End::Next(seed as usize % count)
                }));
            }
            blocks.push(Block { paths });
        }
        let mut expected = vec![0usize; count];
        loop {
            let mut unique = HashMap::new();
            let next = blocks
                .iter()
                .map(|b| {
                    let mut paths = b.paths.clone();
                    for p in &mut paths {
                        if let End::Next(n) = &mut p.end {
                            *n = expected[*n];
                        }
                    }
                    let id = unique.len();
                    *unique.entry(paths).or_insert(id)
                })
                .collect::<Vec<_>>();
            if next == expected {
                break;
            }
            expected = next;
        }
        let actual = crate::devirt::partition::classes(
            &blocks,
            &crate::devirt::budget::Budget::new().unwrap(),
        )
        .unwrap();
        for a in 0..count {
            for b in 0..count {
                assert_eq!(
                    expected[a] == expected[b],
                    actual[a] == actual[b],
                    "count={count}, {a}/{b}"
                );
            }
        }
    }
}

#[test]
fn predecessor_partition_distinguishes_long_chains_and_shared_loops() {
    let mut arena = Expressions::default();
    let mut blocks = (0..4000)
        .map(|i| Block {
            paths: vec![path(End::Next(i + 1))],
        })
        .collect::<Vec<_>>();
    blocks.push(Block {
        paths: vec![path(exit(&mut arena))],
    });
    blocks.push(Block {
        paths: vec![path(End::Next(4001))],
    });
    blocks.push(Block {
        paths: vec![path(End::Next(4002))],
    });
    let classes =
        crate::devirt::partition::classes(&blocks, &crate::devirt::budget::Budget::new().unwrap())
            .unwrap();
    assert_eq!(
        classes[..4001]
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4001
    );
    assert_eq!(classes[4001], classes[4002]);
    assert!(!classes[..4001].contains(&classes[4001]));
}
