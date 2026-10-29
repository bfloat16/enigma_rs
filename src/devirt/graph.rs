//! Recover a native CFG from input cases. Case numbers disappear after this pass.
use super::{
    ir::{Expr, Id},
    lift::{Predicate, Store},
    switch::{Boundary, Session},
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Start {
    Function(u32),
    Continuation(u32),
    Code(u32),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Storage {
    Register(u32),
    Flags,
    Word(u32),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum End {
    Next(usize),
    Transfer {
        registers: [Id; 8],
        flags: Id,
        target: Id,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Path {
    pub conditions: Vec<Predicate>,
    pub stores: Vec<Store>,
    pub assignments: Vec<(u32, Id)>,
    pub end: End,
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Block {
    pub paths: Vec<Path>,
}
pub(crate) struct Graph {
    pub session: Session,
    pub blocks: Vec<Block>,
    pub slots: u32,
    pub start: Start,
}

#[derive(Hash, PartialEq, Eq)]
struct Key {
    pc: u32,
    guest_sp: Option<u32>,
    registers: [super::static_x86::Value; 8],
    flags: super::static_x86::Value,
    memory: Vec<(u32, super::static_x86::Value)>,
    guest_memory: Vec<((u32, u32), super::static_x86::Value)>,
    // Canonical cells plus immutable address/input identities. Numeric facts
    // alone cannot distinguish two different unknown symbolic values.
    expressions: Vec<Id>,
}

impl Graph {
    pub(super) fn recover_session(mut session: Session, start: Start) -> Result<Self> {
        let mut blocks = vec![Block { paths: Vec::new() }];
        let mut states = vec![session.initial.clone()];
        let mut pending = VecDeque::from([0usize]);
        let mut queued = vec![true];
        let mut keys = HashMap::<Key, usize>::new();
        let mut variables = HashMap::new();
        let mut slots = 18;
        let mut processed = 0usize;
        while let Some(block) = pending.pop_front() {
            queued[block] = false;
            let state = states[block].clone();
            blocks[block].paths.clear();
            if processed.is_multiple_of(128) {
                session.budget.check(
                    "recovery",
                    format!(
                        "{start:?}, block={block}, discovered={}, pending={}, expressions={}",
                        blocks.len(),
                        pending.len(),
                        session.expressions.len()
                    ),
                )?;
            }
            processed += 1;
            ensure!(blocks.len() <= 20000, "lifted VM CFG exceeds block bounds");
            let boundaries = session.advance(state)?;
            for boundary in boundaries {
                let boundary = match boundary {
                    Boundary::Case {
                        id,
                        continuation,
                        state,
                    } => Boundary::Continue(session.enter_case(state, id, continuation)?),
                    other => other,
                };
                let path = match boundary {
                    Boundary::Continue(mut state) => {
                        let generalize = state.guest_sp.is_some();
                        let conditions = std::mem::take(&mut state.conditions);
                        let stores = std::mem::take(&mut state.stores);
                        let mut assignments = Vec::new();
                        for r in 0..8 {
                            Self::bind(
                                &mut session,
                                &mut variables,
                                &mut slots,
                                &mut assignments,
                                Storage::Register(r),
                                &mut state.registers[r as usize],
                                generalize,
                            )?;
                        }
                        Self::bind(
                            &mut session,
                            &mut variables,
                            &mut slots,
                            &mut assignments,
                            Storage::Flags,
                            &mut state.flags,
                            generalize,
                        )?;
                        state
                            .cpu
                            .esp()
                            .context("unknown private operand stack at case boundary")?;
                        let mut words = state
                            .bytes
                            .keys()
                            .map(|&at| at & !3)
                            .collect::<BTreeSet<_>>();
                        // Bind disjoint aligned words. Binding an unaligned
                        // spill as well would overwrite a neighboring binding
                        // before all parallel RHS values have been captured.
                        words.extend(state.words.keys().map(|at| at & !3));
                        let mut symbolic = Vec::new();
                        for at in words {
                            let mut value = session.word(&state, at);
                            Self::bind(
                                &mut session,
                                &mut variables,
                                &mut slots,
                                &mut assignments,
                                Storage::Word(at),
                                &mut value,
                                generalize,
                            )?;
                            state.write(&mut session.expressions, at, 4, value);
                            symbolic.push(at);
                            symbolic.push(value);
                        }
                        symbolic.extend(state.registers);
                        symbolic.push(state.flags);
                        state.guest_memory.clear();
                        state.epoch = 0;
                        // Key by control shape, not by every scalar value.
                        // Incoming edges assign their own values to cells;
                        // merged numeric facts are only a proof aid for lifting.
                        let abstract_value = |v: super::static_x86::Value| {
                            if generalize
                                && !v.candidates().is_some_and(|values| {
                                    values.iter().any(|&p| session.analysis_pointer(p))
                                })
                            {
                                super::static_x86::Value::UNKNOWN
                            } else {
                                v
                            }
                        };
                        let key = Key {
                            pc: state.cpu.pc,
                            guest_sp: state.guest_sp,
                            registers: state.cpu.registers.map(abstract_value),
                            flags: abstract_value(state.cpu.flags),
                            memory: state
                                .cpu
                                .live_memory(0)
                                .into_iter()
                                .map(|(a, v)| (a, abstract_value(v)))
                                .collect(),
                            guest_memory: {
                                let mut memory = state
                                    .guest_values
                                    .iter()
                                    .map(|(&address, &value)| (address, abstract_value(value)))
                                    .collect::<Vec<_>>();
                                memory.sort_by_key(|(address, _)| *address);
                                memory
                            },
                            expressions: symbolic,
                        };
                        let next = if let Some(&next) = keys.get(&key) {
                            if generalize {
                                // A block is analyzed with the meet of every
                                // incoming numeric fact. Losing a fact invalidates
                                // its old edges, which are rebuilt on the worklist.
                                let old: &mut super::lift::StateExpressions = &mut states[next];
                                let mut changed = old.cpu.join(&state.cpu, &session.image);
                                for (address, value) in &mut old.guest_values {
                                    let joined = value.join(state.guest_values[address]);
                                    changed |= joined != *value;
                                    *value = joined;
                                }
                                if changed && !queued[next] {
                                    pending.push_back(next);
                                    queued[next] = true;
                                }
                            }
                            next
                        } else {
                            let next = blocks.len();
                            keys.insert(key, next);
                            blocks.push(Block { paths: Vec::new() });
                            states.push(state);
                            pending.push_back(next);
                            queued.push(true);
                            next
                        };
                        Path {
                            conditions,
                            stores,
                            assignments,
                            end: End::Next(next),
                        }
                    }
                    Boundary::Case { .. } => unreachable!(),
                    Boundary::Host { state, target } => Path {
                        conditions: state.conditions,
                        stores: state.stores,
                        assignments: Vec::new(),
                        end: End::Transfer {
                            registers: state.registers,
                            flags: state.flags,
                            target,
                        },
                    },
                    Boundary::Return(state) => {
                        let pointer = session.expressions.input(4);
                        let target = session.expressions.intern(Expr::Load(
                            pointer,
                            32,
                            iced_x86::Register::SS,
                            0,
                        ));
                        Path {
                            conditions: state.conditions,
                            stores: state.stores,
                            assignments: Vec::new(),
                            end: End::Transfer {
                                registers: state.registers,
                                flags: state.flags,
                                target,
                            },
                        }
                    }
                };
                if !blocks[block].paths.contains(&path) {
                    blocks[block].paths.push(path);
                }
            }
        }
        let mut graph = Self {
            session,
            blocks,
            slots,
            start,
        };
        graph.simplify()?;
        Ok(graph)
    }

    fn bind(
        session: &mut Session,
        variables: &mut HashMap<Storage, u32>,
        slots: &mut u32,
        assignments: &mut Vec<(u32, Id)>,
        storage: Storage,
        value: &mut Id,
        generalize: bool,
    ) -> Result<()> {
        let immutable = matches!(
            session.expressions.node(*value),
            Expr::Constant(_)
                | Expr::Input(_)
                | Expr::PrivateAddress(_)
                | Expr::Function(_)
                | Expr::Continuation(_)
                | Expr::Bytecode(_)
                | Expr::ImageBase
        ) || session.expressions.stack_offset(*value).is_some()
            || matches!(session.expressions.node(*value), Expr::GuestPointer(input)
                if matches!(session.expressions.node(*input), Expr::Input(_)));
        let control = matches!(
            session.expressions.node(*value),
            Expr::PrivateAddress(_)
                | Expr::Function(_)
                | Expr::Continuation(_)
                | Expr::Bytecode(_)
                | Expr::ImageBase
        ) || session
            .expressions
            .value(*value)
            .is_some_and(|p| session.analysis_pointer(p))
            || session.expressions.stack_offset(*value).is_some();
        if if generalize { control } else { immutable } {
            return Ok(());
        }
        let slot = match storage {
            Storage::Register(r) => 9 + r,
            Storage::Flags => 17,
            _ => *variables.entry(storage).or_insert_with(|| {
                let slot = *slots;
                *slots += 1;
                slot
            }),
        };
        let pointer =
            session.expressions.guest_pointer(*value) || session.expressions.relocatable(*value);
        let input = session.expressions.intern(Expr::Cell(slot));
        let input = if pointer {
            session.expressions.intern(Expr::GuestPointer(input))
        } else {
            input
        };
        if *value != input {
            assignments.push((slot, *value));
            *value = input;
        }
        ensure!(*slots <= 32768, "lifted VM storage exceeds bounds");
        Ok(())
    }

    fn collect_expressions(&self, id: Id, visited: &mut HashSet<Id>) {
        if !visited.insert(id) {
            return;
        }
        match *self.session.expressions.node(id) {
            Expr::Extract(a, _, _)
            | Expr::Unary(_, a, _)
            | Expr::GuestPointer(a)
            | Expr::Load(a, _, _, _) => self.collect_expressions(a, visited),
            Expr::Insert(a, b, _, _) | Expr::Binary(_, a, b, _) => {
                self.collect_expressions(a, visited);
                self.collect_expressions(b, visited);
            }
            Expr::Flags(_, a, b, c, _) => {
                self.collect_expressions(a, visited);
                self.collect_expressions(b, visited);
                self.collect_expressions(c, visited);
            }
            _ => {}
        }
    }
    pub(crate) fn simplify(&mut self) -> Result<()> {
        for _ in 0..8 {
            super::demand::prune(self)?;
            let classes = super::partition::classes(&self.blocks, &self.session.budget)?;
            let mut changed = false;
            for block in &mut self.blocks {
                if block.paths.len() > 1 {
                    let first = &block.paths[0];
                    let same = block.paths.iter().all(|path| {
                        path.stores == first.stores
                            && path.assignments == first.assignments
                            && match (&path.end, &first.end) {
                                (End::Next(a), End::Next(b)) => classes[*a] == classes[*b],
                                (a, b) => a == b,
                            }
                    });
                    if same {
                        block.paths.truncate(1);
                        block.paths[0].conditions.clear();
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    pub fn starts(&self) -> HashSet<Start> {
        let mut result = HashSet::new();
        let mut needed = HashSet::new();
        for block in &self.blocks {
            for path in &block.paths {
                let mut roots = path.conditions.iter().map(|p| p.flags).collect::<Vec<_>>();
                for store in &path.stores {
                    roots.extend([store.address, store.value]);
                }
                roots.extend(path.assignments.iter().map(|&(_, value)| value));
                if let End::Transfer {
                    registers,
                    flags,
                    target,
                } = &path.end
                {
                    roots.extend(registers);
                    roots.extend([*flags, *target]);
                }
                for root in roots {
                    self.collect_expressions(root, &mut needed);
                }
            }
        }
        for id in needed {
            if let Expr::Continuation(offset) = *self.session.expressions.node(id) {
                result.insert(Start::Continuation(offset));
            }
            if let Expr::Bytecode(offset) = *self.session.expressions.node(id) {
                result.insert(Start::Code(offset));
            }
        }
        result
    }
}
