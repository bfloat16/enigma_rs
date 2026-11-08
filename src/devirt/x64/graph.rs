//! Recover a native CFG from input cases. Case numbers disappear after this pass.
use super::{
    ir::{Expr, Id},
    lift::{Predicate, Store},
    switch::{Boundary, Session},
};
use anyhow::{Context, Result, ensure};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Start {
    Function(u64),
    Continuation(u64),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Storage {
    Register(u64),
    Flags,
    Word(u64),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum End {
    Next(usize),
    Transfer {
        registers: [Id; 16],
        flags: Id,
        target: Id,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Path {
    pub conditions: Vec<Predicate>,
    pub stores: Vec<Store>,
    pub assignments: Vec<(u64, Id)>,
    pub end: End,
}
impl Path {
    pub(crate) fn successor(&mut self) -> Option<&mut usize> {
        match &mut self.end {
            End::Next(target) => Some(target),
            _ => None,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Block {
    pub paths: Vec<Path>,
}
pub(crate) struct Graph {
    pub session: Session,
    pub blocks: Vec<Block>,
    pub slots: u64,
    pub start: Start,
}

#[derive(Hash, PartialEq, Eq)]
struct Key {
    pc: u64,
    guest_sp: Option<u64>,
    registers: [super::cpu::Value; 16],
    flags: super::cpu::Value,
    memory: Vec<(u64, super::cpu::Value)>,
    guest_memory: Vec<((u64, u64), super::cpu::Value)>,
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
        let mut keys = HashMap::<Key, usize>::default();
        let mut variables = HashMap::default();
        let mut slots = 34;
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
            ensure!(
                blocks.len() <= 65536,
                "lifted VM CFG exceeds block bounds: {} > 65536",
                blocks.len()
            );
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
                        if generalize {
                            state.retire_stack(&mut session.expressions)?;
                        }
                        let conditions = std::mem::take(&mut state.conditions);
                        let stores = std::mem::take(&mut state.stores);
                        let mut assignments = Vec::new();
                        for r in 0..16 {
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
                        let mut words = state.bytes.keys().map(|&at| at & !7).collect::<Vec<_>>();
                        // Bind disjoint aligned words. Binding an unaligned
                        // spill as well would overwrite a neighboring binding
                        // before all parallel RHS values have been captured.
                        words.extend(
                            state
                                .words
                                .keys()
                                .flat_map(|&at| [at & !7, at.wrapping_add(7) & !7]),
                        );
                        words.sort_unstable();
                        words.dedup();
                        let mut symbolic = Vec::with_capacity(words.len() * 2 + 17);
                        for at in words {
                            let mut value = session.word(&state, at)?;
                            Self::bind(
                                &mut session,
                                &mut variables,
                                &mut slots,
                                &mut assignments,
                                Storage::Word(at),
                                &mut value,
                                generalize,
                            )?;
                            if state.words.get(&at) != Some(&value) {
                                state.write(&mut session.expressions, at, 8, value);
                            }
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
                        let abstract_value = |v: super::cpu::Value| {
                            if generalize
                                && !v.candidates().is_some_and(|values| {
                                    values.iter().any(|&p| session.analysis_pointer(p))
                                })
                            {
                                super::cpu::Value::UNKNOWN
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
                                changed |= old.retired_stack < state.retired_stack;
                                old.retired_stack = old.retired_stack.max(state.retired_stack);
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
                            64,
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
        variables: &mut HashMap<Storage, u64>,
        slots: &mut u64,
        assignments: &mut Vec<(u64, Id)>,
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
                | Expr::RuntimeData(_)
                | Expr::ImageBase
        ) || session.expressions.stack_offset(*value).is_some()
            || matches!(session.expressions.node(*value), Expr::GuestPointer(input)
                if matches!(session.expressions.node(*input), Expr::Input(_)));
        let control = matches!(
            session.expressions.node(*value),
            Expr::PrivateAddress(_)
                | Expr::Function(_)
                | Expr::Continuation(_)
                | Expr::RuntimeData(_)
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
            Storage::Register(r) => 17 + r,
            Storage::Flags => 33,
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
            Expr::Flags(_, a, b, c, _) | Expr::Divide(a, b, c, _, _, _) => {
                self.collect_expressions(a, visited);
                self.collect_expressions(b, visited);
                self.collect_expressions(c, visited);
            }
            _ => {}
        }
    }
    pub(crate) fn simplify(&mut self) -> Result<()> {
        for _ in 0..16 {
            // An edge with no effects can absorb an unconditional assignment
            // block. This exposes equivalent branches whose effects were split
            // across different block boundaries by opaque VM instructions.
            let mut forwarded = Vec::new();
            for (index, block) in self.blocks.iter().enumerate() {
                for (path_index, path) in block.paths.iter().enumerate() {
                    if !path.assignments.is_empty() || !path.stores.is_empty() {
                        continue;
                    }
                    let End::Next(next) = path.end else {
                        continue;
                    };
                    if next == index {
                        continue;
                    }
                    let [successor] = self.blocks[next].paths.as_slice() else {
                        continue;
                    };
                    if successor.conditions.is_empty()
                        && successor.stores.is_empty()
                        && matches!(successor.end, End::Next(_))
                        && (path.end != successor.end || path.assignments != successor.assignments)
                    {
                        forwarded.push((
                            index,
                            path_index,
                            successor.assignments.clone(),
                            successor.end.clone(),
                        ));
                    }
                }
            }
            let mut changed = !forwarded.is_empty();
            for (index, path, assignments, end) in forwarded {
                self.blocks[index].paths[path].assignments = assignments;
                self.blocks[index].paths[path].end = end;
            }
            super::demand::prune(self)?;
            let classes = super::partition::classes(
                self.blocks.iter().map(|b| b.paths.clone()),
                Path::successor,
                &self.session.budget,
            )?;
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
        let mut result = HashSet::default();
        let mut needed = HashSet::default();
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
        }
        result
    }
}
