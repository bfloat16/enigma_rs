//! Specialize a switch VM using its serialized cases and input bytecode.
use super::{
    cpu::{Image, State, Value},
    graph::Start,
    ir::{Expr, Expressions, Id},
    lift::StateExpressions,
    profile::Profile,
};
use crate::common::io::u32_at;
use anyhow::{Context, Result, bail, ensure};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::sync::Arc;

pub(crate) enum Boundary {
    Continue(StateExpressions),
    Case {
        id: u64,
        continuation: u64,
        state: StateExpressions,
    },
    Host {
        state: StateExpressions,
        target: Id,
    },
    Return(StateExpressions),
}

pub(crate) struct Session {
    pub budget: super::budget::Budget,
    pub expressions: Expressions,
    pub image: Image,
    pub profile: Arc<Profile>,
    pub base: u64,
    pub loader_base: u64,
    pub dispatch: u64,
    pub heap: u64,
    pub context: u64,
    pub stack: u64,
    pub stop: u64,
    pub callbacks: u64,
    entry: u64,
    entry_size: u64,
    decoder: u64,
    trampoline: u64,
    pub initial: StateExpressions,
    cursor: u64,
    compiled: HashMap<u64, (u64, u64)>,
    trampolines: HashMap<u64, u64>,
    pub minimum_stack: u64,
    pub guest_layout: Option<[u64; 17]>,
    pc_scores: HashMap<u64, usize>,
}

fn aligned(value: u64, size: u64) -> Result<u64> {
    Ok(value
        .checked_add(size - 1)
        .context("analysis address overflow")?
        & !(size - 1))
}

impl Session {
    // Conservatively retain any value that could name loader code, bytecode,
    // callbacks or the private operand frame. Ordinary scalar constants may
    // join, but these values must remain available to decode the next case.
    pub fn analysis_pointer(&self, value: u64) -> bool {
        (self.loader_base..self.dispatch).contains(&value)
            || (self.dispatch..self.stop.saturating_add(0x2000)).contains(&value)
    }
    #[cfg(test)]
    pub fn synthetic_program(bytes: Vec<u8>) -> Self {
        let stack = 0x200080000;
        let mut expressions = Expressions::default();
        let mut image = Image::default();
        image.add(0x1000, bytes.clone()).unwrap();
        let mut initial = StateExpressions::new(
            State::new(0x1000, stack),
            &mut expressions,
            stack - 0x10000,
            stack + 0x10000,
        );
        let stop = stack + 0x20000;
        initial.guest_sp = Some(stack + 0x100);
        initial.cpu.write(&image, stack, 8, Value::constant(stop));
        let target = expressions.constant(stop);
        initial.write(&mut expressions, stack, 8, target);
        Self {
            budget: super::budget::Budget::new().unwrap(),
            expressions,
            image,
            profile: Arc::new(Profile {
                base: 0x140000000,
                runtime_rva: 0,
                streams: Vec::new(),
                handlers: Default::default(),
                patch: [0; 12],
                dispatcher: Vec::new(),
                decoder: 0,
            }),
            base: 0x140000000,
            loader_base: 0x1fff00000,
            dispatch: 0x200000000,
            heap: 0,
            context: 0,
            stack,
            stop,
            callbacks: stop + 16,
            entry: 0x1000,
            entry_size: bytes.len() as u64,
            decoder: 0x200000100,
            trampoline: 0,
            initial,
            cursor: 0,
            compiled: HashMap::default(),
            trampolines: HashMap::default(),
            minimum_stack: stack,
            guest_layout: None,
            pc_scores: HashMap::default(),
        }
    }
    pub fn fixed_host_header(&mut self, header: &[u8]) -> Result<()> {
        if header.is_empty() {
            return Ok(());
        }
        let nt = u32_at(header, 0x3c)? as u64;
        let optional = nt + 24;
        let mut bytes = HashMap::default();
        // These fields survive PE reconstruction and are mapped read-only.
        // Do not specialize section counts, OEP, SizeOfImage or the new IAT.
        for (offset, length) in [
            (0, 2),
            (0x3c, 4),
            (nt, 4),
            (nt + 4, 2),
            (optional, 2),
            (optional + 108, 4),
            (optional + 112 + 14 * 8, 8),
        ] {
            if offset == optional + 112 + 14 * 8
                && header
                    .get(offset as usize..(offset + length) as usize)
                    .is_none_or(|data| data.iter().any(|&byte| byte != 0))
            {
                continue;
            }
            for index in 0..length {
                bytes.insert(
                    offset + index,
                    *header
                        .get((offset + index) as usize)
                        .context("fixed PE header field is outside headers")?,
                );
            }
        }
        self.initial.image_base = self.base;
        self.initial.fixed_header = std::sync::Arc::new(bytes);
        Ok(())
    }
    pub fn from_start(
        loader: &[u8],
        profile: Arc<Profile>,
        start: Start,
        entry: u64,
        budget: super::budget::Budget,
    ) -> Result<Self> {
        let base = profile.base;
        let (entry, continuation) = match start {
            Start::Function(rva) => (rva, None),
            Start::Continuation(at) => (entry, Some(at)),
        };
        ensure!(
            profile.streams.iter().any(|s| s.0 == entry),
            "no VM stream for entry {entry:#x}"
        );
        let loader_size = u64::try_from(loader.len())?;
        let maximum = profile
            .streams
            .iter()
            .map(|s| s.0)
            .max()
            .unwrap_or(0)
            .max(loader_size);
        // Bytecode offsets and guest RVAs are different address spaces. Loader
        // functions can have the same RVA as a serialized bytecode offset.
        // Keep the bytecode image beyond the guest's possible Loader mapping.
        let loader_base = aligned(
            base.checked_add(maximum)
                .and_then(|at| at.checked_add(loader_size))
                .context("analysis Loader address overflow")?,
            0x10000,
        )?;
        let dispatch = aligned(
            loader_base
                .checked_add(loader_size)
                .context("Loader extent overflow")?,
            0x10000,
        )?;
        let heap = aligned(
            dispatch
                .checked_add(profile.dispatcher.len().try_into()?)
                .context("dispatcher extent overflow")?,
            0x10000,
        )?;
        let context = heap
            .checked_add(0x1000000)
            .context("analysis address overflow")?;
        let stack = context
            .checked_add(0x20000)
            .context("analysis address overflow")?;
        let stop = stack
            .checked_add(0x20000)
            .context("analysis address overflow")?;
        let callbacks = stop.checked_add(16).context("analysis address overflow")?;
        let mut image = Image::default();
        image.add(loader_base, loader.to_vec())?;
        // Runtime object contents are not supplied by the input VM stream.
        // Keep unwritten fields unknown instead of specializing them to zero.
        let mut dispatcher = profile.dispatcher.clone();
        for (index, &at) in profile.patch[..9].iter().enumerate() {
            let value = match index {
                3 => dispatch,
                6 => dispatch + profile.patch[10],
                _ => callbacks + index as u64 * 16,
            };
            dispatcher[at as usize..at as usize + 8].copy_from_slice(&value.to_le_bytes());
        }
        image.add(dispatch, dispatcher)?;
        let trampoline = dispatch - 0x1000;
        let mut trampoline_code = vec![0xe9];
        trampoline_code
            .extend(i32::try_from(dispatch as i64 - (trampoline + 5) as i64)?.to_le_bytes());
        image.replace_region(trampoline, trampoline_code)?;
        let start = if continuation.is_some() {
            callbacks + 0x1000
        } else {
            base + entry
        };
        let code = if let Some(offset) = continuation {
            let source = loader_base
                .checked_add(offset)
                .context("continuation address overflow")?;
            ensure!(
                profile
                    .streams
                    .iter()
                    .any(|s| (s.1..s.1 + s.2 as u64).contains(&offset)),
                "VM continuation outside streams"
            );
            let mut code = vec![0x6a, 0, 0xff, 0x35, 6, 0, 0, 0, 0xff, 0x25, 8, 0, 0, 0];
            code.extend(source.to_le_bytes());
            code.extend((dispatch + profile.patch[9]).to_le_bytes());
            code
        } else {
            let mut code = vec![0xe8];
            code.extend(
                i32::try_from(trampoline as i64 - (base + entry + 5) as i64)?.to_le_bytes(),
            );
            code
        };
        let entry_size = code.len() as u64;
        image.replace_region(start, code)?;
        let cpu = State::new(start, stack);
        let mut expressions = Expressions::default();
        expressions.private_range(loader_base, loader.len().try_into()?);
        expressions.private_range(dispatch, profile.dispatcher.len().try_into()?);
        expressions.private_range(heap, context - heap);
        expressions.private_range(context, stop - context);
        let mut initial =
            StateExpressions::new(cpu, &mut expressions, stack - 0x10000, stack + 0x10000);
        initial.internal.push((context, 0x10000));
        initial.image_signature = crate::common::io::u16_at(loader, 0)?;
        initial.code_ranges = profile
            .streams
            .iter()
            .map(|s| (loader_base + s.1, s.2 as u64, loader_base))
            .collect();
        let decoder = dispatch + profile.decoder;
        Ok(Self {
            budget,
            expressions,
            image,
            profile,
            base,
            loader_base,
            dispatch,
            heap,
            context,
            stack,
            stop,
            callbacks,
            entry: start,
            entry_size,
            decoder,
            trampoline,
            initial,
            cursor: heap,
            compiled: HashMap::default(),
            trampolines: HashMap::default(),
            minimum_stack: stack,
            guest_layout: None,
            pc_scores: HashMap::default(),
        })
    }

    fn allocate(&mut self, bytes: Vec<u8>) -> Result<u64> {
        let at = self.cursor;
        self.cursor = aligned(
            at.checked_add(bytes.len().try_into()?)
                .context("case extent overflow")?,
            16,
        )?;
        ensure!(self.cursor < self.context, "analysis case arena exhausted");
        self.image.add(at, bytes)?;
        Ok(at)
    }

    fn argument(&mut self, state: &StateExpressions, index: u64) -> Result<u64> {
        state.check_private_read(state.cpu.esp()? + 0x28 + index * 8, 8)?;
        state
            .cpu
            .read(&self.image, state.cpu.esp()? + 0x28 + index * 8, 8)
            .require("VM callback argument")
    }
    fn argument_expr(&mut self, state: &StateExpressions, index: u64) -> Result<Id> {
        let address = state.cpu.esp()? + 0x28 + index * 8;
        let pointer = self.expressions.intern(Expr::PrivateAddress(address));
        state.read(&mut self.expressions, &self.image, address, 8, pointer)
    }

    fn callback_return(
        &mut self,
        state: &mut StateExpressions,
        value: Value,
        _consumed: u64,
    ) -> Result<()> {
        state.cpu.return_from(&self.image, 0)?;
        state.cpu.registers[0] = value;
        for r in [1, 2, 8, 9, 10, 11] {
            state.cpu.registers[r] = Value::UNKNOWN;
        }
        // These x64 callbacks clobber volatile GPRs and arithmetic flags; the VM's
        // control flags remain those of its saved native register image.
        let mut flags = Value::unknown_flags();
        flags.bits |= state.cpu.flags.bits & !0x8d5;
        flags.known |= state.cpu.flags.known & !0x8d5;
        state.cpu.flags = flags;
        let amount = self.expressions.constant(8);
        state.registers[4] =
            self.expressions
                .binary(iced_x86::Mnemonic::Add, state.registers[4], amount, 64);
        state.registers[0] = if let Some(value) = value.get() {
            self.expressions.constant(value)
        } else {
            self.expressions.fresh_input()
        };
        for r in [1, 2, 8, 9, 10, 11] {
            state.registers[r] = self.expressions.fresh_input();
        }
        let preserved = self.expressions.constant(!0x8d5);
        let preserved =
            self.expressions
                .binary(iced_x86::Mnemonic::And, state.flags, preserved, 64);
        let unknown = self.expressions.fresh_input();
        let mask = self.expressions.constant(0x8d5);
        let written = self
            .expressions
            .binary(iced_x86::Mnemonic::And, unknown, mask, 64);
        state.flags = self
            .expressions
            .binary(iced_x86::Mnemonic::Or, preserved, written, 64);
        Ok(())
    }

    pub fn enter_case(
        &mut self,
        mut state: StateExpressions,
        id: u64,
        continuation: u64,
    ) -> Result<StateExpressions> {
        // The DLL caches handlers by selector only. A different tail for an
        // already compiled selector is not another specialization of the VM.
        let target = if let Some(&(target, tail)) = self.compiled.get(&id) {
            ensure!(
                tail == continuation,
                "VM case {id:#x} was cached with a different continuation"
            );
            target
        } else {
            let mut bytes = self
                .profile
                .handlers
                .get(&id)
                .with_context(|| format!("unknown VM case {id:#x}"))?
                .clone();
            let delta =
                i32::try_from(continuation as i64 - (self.cursor + bytes.len() as u64 + 5) as i64)?;
            bytes.push(0xe9);
            bytes.extend(delta.to_le_bytes());
            let at = self.allocate(bytes)?;
            self.compiled.insert(id, (at, continuation));
            at
        };
        self.callback_return(&mut state, Value::constant(target), 8)?;
        state.cpu.step += 1;
        Ok(state)
    }

    fn activate(&mut self, state: &mut StateExpressions) -> Result<()> {
        if state.guest_sp.is_some() {
            return Ok(());
        }
        let frame = state.cpu.registers[5].require("VM frame")?;

        let span = self
            .stack
            .checked_sub(frame)
            .context("VM frame is above its input stack")?;
        ensure!(span <= 0x10000, "VM frame size exceeds bounds");
        let mut offsets = [None; 17];
        for offset in (0..span).step_by(8) {
            let value = self.word(state, frame + offset)?;
            if state.initializer_words.get(&(frame + offset)) == Some(&value) {
                continue;
            }
            if let Expr::Input(register) = *self.expressions.node(value)
                && register <= 16
            {
                let previous = offsets[register as usize].replace(offset);
                ensure!(
                    previous.is_none(),
                    "ambiguous virtual register {register} placement: {previous:x?} and {offset:#x}, frame span={span:#x}"
                );
            }
        }
        let layout = offsets
            .into_iter()
            .map(|offset| {
                offset.context("VM initializer did not expose all x64 registers and flags")
            })
            .collect::<Result<Vec<_>>>()?;
        let layout: [u64; 17] = layout.try_into().unwrap();
        let sp = self.word(state, frame + layout[4])?;
        let sp = self.expressions.intern(Expr::GuestPointer(sp));
        state.write(&mut self.expressions, frame + layout[4], 8, sp);
        state.guest_sp = Some(frame + layout[4]);
        state.registers[4] = self
            .expressions
            .intern(Expr::PrivateAddress(state.cpu.esp()?));
        state.registers[5] = self.expressions.intern(Expr::PrivateAddress(frame));
        self.guest_layout = Some(layout);
        state.initializer_words.clear();

        Ok(())
    }

    pub fn advance(&mut self, initial: StateExpressions) -> Result<Vec<Boundary>> {
        let mut pending = vec![initial];
        let mut visited = HashSet::default();
        let mut seen_pc = HashSet::default();
        let mut results = Vec::new();
        let mut instructions = 0usize;
        while let Some(mut state) = pending.pop() {
            loop {
                instructions += 1;
                if instructions.is_multiple_of(256) {
                    self.budget.check(
                        "handler execution",
                        format!(
                            "pc={:#x}, instructions={instructions}, VM step={}",
                            state.cpu.pc, state.cpu.step
                        ),
                    )?;
                }
                ensure!(
                    instructions <= 200000,
                    "VM case control flow exceeds analysis bounds"
                );
                let pc = state.cpu.pc;
                if pc == self.dispatch + self.profile.patch[10] {
                    // This routine only relocates the private operand frame.
                    // The lifted frame has no physical capacity or guest alias.
                    state.cpu.pc = self.decoder;
                    continue;
                }
                if pc == self.decoder {
                    if let (Some(_), Some((&offset, _))) = (
                        self.guest_layout,
                        self.pc_scores.iter().max_by_key(|(_, score)| *score),
                    ) {
                        let frame = state.cpu.registers[5].require("VM frame")?;
                        let numeric = state.cpu.read(&self.image, frame + offset, 8).get();
                        if numeric.is_none() {
                            let target = self.word(&state, frame + offset)?;
                            bail!(
                                "VM bytecode cursor is unproven at step {}, frame offset {offset:#x}: {}",
                                state.cpu.step,
                                self.describe(target, 8)
                            );
                        } else if let Some(pointer) = numeric
                            && self.profile.streams.iter().any(|s| {
                                (self.loader_base + s.1..self.loader_base + s.1 + s.2 as u64)
                                    .contains(&pointer)
                            })
                        {
                            let value = self.expressions.intern(Expr::PrivateAddress(pointer));
                            state.write(&mut self.expressions, frame + offset, 8, value);
                        }
                    }
                    if let Some(pointer) = state.cpu.registers[0].get() {
                        let relative = pointer.wrapping_sub(self.base);
                        if self
                            .profile
                            .streams
                            .iter()
                            .any(|s| (s.1..s.1 + s.2 as u64).contains(&relative))
                        {
                            let relocated = self.loader_base + relative;
                            state.cpu.registers[0] = Value::constant(relocated);
                            state.registers[0] =
                                self.expressions.intern(Expr::PrivateAddress(relocated));
                        }
                    }
                }
                if let Some(sp) = state.cpu.registers[4].get() {
                    self.minimum_stack = self.minimum_stack.min(sp);
                }
                if pc == self.stop {
                    results.push(Boundary::Return(state));
                    break;
                }
                if (self.callbacks..self.callbacks + 9 * 16).contains(&pc) {
                    ensure!(
                        (pc - self.callbacks).is_multiple_of(16),
                        "invalid VM callback address"
                    );
                    let index = (pc - self.callbacks) / 16;
                    if index == 7 {
                        let frame = state.cpu.registers[5].require("VM operand frame")?;
                        if state.cpu.step == 0 {
                            state.initializer_words = state.words.clone();
                        }
                        if state.cpu.step == 1 && state.guest_sp.is_none() {
                            self.activate(&mut state)?;
                        }
                        let id = self.argument(&state, 0).with_context(|| {
                            format!(
                                "VM selector at step {}, eax={:?}, frame={frame:#x}, loader={:#x}",
                                state.cpu.step, state.cpu.registers[0], self.loader_base
                            )
                        })?;
                        let continuation = self.argument(&state, 1)?;
                        results.push(Boundary::Case {
                            id,
                            continuation,
                            state,
                        });
                        break;
                    }
                    let mut return_expr = None;
                    let (value, consumed) = match index {
                        0 => {
                            let source = self.argument(&state, 0)?;
                            let target = if let Some(&target) = self.trampolines.get(&source) {
                                target
                            } else {
                                let mut bytes =
                                    vec![0x6a, 0, 0xff, 0x35, 6, 0, 0, 0, 0xff, 0x25, 8, 0, 0, 0];
                                bytes.extend(source.to_le_bytes());
                                bytes.extend((self.dispatch + self.profile.patch[9]).to_le_bytes());
                                let target = self.allocate(bytes)?;
                                self.trampolines.insert(source, target);
                                target
                            };
                            (Value::constant(target), 4)
                        }
                        1 => (Value::constant(self.context), 4),
                        2 => (Value::constant(self.base), 0),
                        4 => {
                            let source = self.argument(&state, 0)?;
                            let target = self
                                .profile
                                .streams
                                .iter()
                                .find(|s| self.base + s.0 == source)
                                .map_or(0, |s| self.loader_base + s.1);
                            (Value::constant(target), 4)
                        }
                        5 => {
                            let source = self.argument(&state, 0)?;
                            let target = self
                                .profile
                                .streams
                                .iter()
                                .map(|s| self.loader_base + s.1)
                                .filter(|&p| {
                                    (source.wrapping_sub(p) as i64) > 0
                                        && source.wrapping_sub(p) < i64::MAX as u64
                                })
                                .min_by_key(|&p| source.wrapping_sub(p))
                                .unwrap_or(0);
                            (Value::constant(target), 4)
                        }
                        8 => {
                            let source_expr = self.argument_expr(&state, 0)?;
                            let source = state
                                .cpu
                                .read(&self.image, state.cpu.esp()? + 0x28, 8)
                                .get();
                            let target_expr = self.argument_expr(&state, 1)?;
                            let target = state
                                .cpu
                                .read(&self.image, state.cpu.esp()? + 0x30, 8)
                                .get();
                            let size = (self.argument(&state, 2)? as i64).max(0) as u64;
                            ensure!(size <= 0x1000000, "VM copy extent exceeds analysis bounds");
                            // RVA 0x1486E8 in the inspected DLL is a forward
                            // byte loop, including its behavior on overlap.
                            for offset in 0..size {
                                if offset.is_multiple_of(256) {
                                    self.budget.check(
                                        "runtime copy",
                                        format!("offset={offset}, size={size}"),
                                    )?;
                                }
                                let delta = self.expressions.constant(offset);
                                let pointer = self.expressions.binary(
                                    iced_x86::Mnemonic::Add,
                                    source_expr,
                                    delta,
                                    64,
                                );
                                let (value, numeric) = if let Some(source) =
                                    source.filter(|_| !self.expressions.guest_pointer(pointer))
                                {
                                    let at = source.wrapping_add(offset);
                                    (
                                        state.read(
                                            &mut self.expressions,
                                            &self.image,
                                            at,
                                            1,
                                            pointer,
                                        )?,
                                        state.cpu.read(&self.image, at, 1),
                                    )
                                } else {
                                    state.guest_read(
                                        &mut self.expressions,
                                        pointer,
                                        1,
                                        iced_x86::Register::DS,
                                    )
                                };
                                if let Some(target) =
                                    target.filter(|_| !self.expressions.guest_pointer(target_expr))
                                {
                                    let at = target.wrapping_add(offset);
                                    state.write(&mut self.expressions, at, 1, value);
                                    state.cpu.write(&self.image, at, 1, numeric);
                                } else {
                                    let address = self.expressions.binary(
                                        iced_x86::Mnemonic::Add,
                                        target_expr,
                                        delta,
                                        64,
                                    );
                                    state.guest_write(
                                        &mut self.expressions,
                                        address,
                                        1,
                                        value,
                                        numeric,
                                        iced_x86::Register::DS,
                                    );
                                    // This write can alias cached guest values.
                                    state.guest_values.clear();
                                }
                            }
                            return_expr = Some(target_expr);
                            (target.map_or(Value::UNKNOWN, Value::constant), 12)
                        }
                        _ => bail!("unexpected VM callback {index}"),
                    };
                    let source = if index == 0 {
                        Some(self.argument(&state, 0)?)
                    } else {
                        None
                    };
                    self.callback_return(&mut state, value, consumed)?;
                    if let Some(value) = return_expr {
                        state.registers[0] = value;
                    }
                    if index == 2 {
                        state.registers[0] = self.expressions.intern(Expr::ImageBase);
                    }
                    if let Some(source) = source {
                        let offset = source.wrapping_sub(self.loader_base);
                        state.registers[0] = if self
                            .profile
                            .streams
                            .iter()
                            .any(|s| (s.1..s.1 + s.2 as u64).contains(&offset))
                        {
                            self.expressions.intern(Expr::Continuation(offset))
                        } else {
                            self.expressions.intern(Expr::Function(source - self.base))
                        };
                    }
                    continue;
                }
                let internal = (self.entry..self.entry + self.entry_size).contains(&pc)
                    && state.cpu.step == 0
                    || pc == self.trampoline
                    || (self.dispatch..self.dispatch + self.profile.dispatcher.len() as u64)
                        .contains(&pc)
                    || (self.heap..self.cursor).contains(&pc);
                if !internal {
                    ensure!(
                        !self.analysis_pointer(pc),
                        "x64 transfer depends on unresolved VM runtime state at {pc:#x}"
                    );
                    let target = self.expressions.intern(Expr::Function(
                        pc.checked_sub(self.base)
                            .context("native target below image base")?,
                    ));
                    results.push(Boundary::Host { state, target });
                    break;
                }
                if !seen_pc.insert(pc) {
                    // Straight-line instructions cannot close a loop. Avoid
                    // copying and sorting the entire memory at every opcode.
                    let key = (
                        pc,
                        state.cpu.registers[4].get(),
                        state.cpu.registers,
                        state.cpu.flags,
                        state.registers,
                        state.flags,
                        state.conditions.clone(),
                        state
                            .cpu
                            .live_memory(state.cpu.registers[4].get().unwrap_or(0)),
                    );
                    if !visited.insert(key) {
                        bail!("VM internal loop repeats at {pc:#x} without a boundary");
                    }
                }
                let i = self.image.instruction(pc)?;
                if (self.dispatch..self.dispatch + self.profile.dispatcher.len() as u64)
                    .contains(&pc)
                    && i.mnemonic() == iced_x86::Mnemonic::Mov
                    && i.op1_kind() == iced_x86::OpKind::Memory
                    && i.memory_base() == iced_x86::Register::RBP
                {
                    let value = super::cpu::operand(&state.cpu, &self.image, &i, 1)?;
                    if let Some(pointer) = value.get()
                        && self.profile.streams.iter().any(|s| {
                            (self.loader_base + s.1..self.loader_base + s.1 + s.2 as u64)
                                .contains(&pointer)
                        })
                    {
                        let at =
                            super::cpu::address(&state.cpu, &i)?.require("VM control field")?;
                        let frame = state.cpu.registers[5].require("VM frame")?;
                        *self.pc_scores.entry(at.wrapping_sub(frame)).or_default() += 1;
                    }
                }
                if i.mnemonic() == iced_x86::Mnemonic::Ret {
                    let sp = state.registers[4];
                    let (target, value) = if self.expressions.guest_pointer(sp) {
                        state.guest_read(&mut self.expressions, sp, 8, iced_x86::Register::SS)
                    } else {
                        let esp = state.cpu.esp()?;
                        (self.word(&state, esp)?, state.cpu.read(&self.image, esp, 8))
                    };
                    let numeric = value.get();
                    let is_continuation = numeric
                        .is_some_and(|pc| self.trampolines.values().any(|&target| target == pc));
                    let within = !is_continuation
                        && numeric.is_some_and(|pc| {
                            pc == self.stop
                                || (self.dispatch
                                    ..self.dispatch + self.profile.dispatcher.len() as u64)
                                    .contains(&pc)
                                || (self.heap..self.cursor).contains(&pc)
                        });
                    if !within {
                        let consumed = if i.op_count() > 0 {
                            i.immediate16() as u64
                        } else {
                            0
                        };
                        let amount = self.expressions.constant(8 + consumed);
                        state.registers[4] = self.expressions.binary(
                            iced_x86::Mnemonic::Add,
                            state.registers[4],
                            amount,
                            64,
                        );
                        state.cpu.registers[4] = state.cpu.registers[4]
                            .get()
                            .map_or(Value::UNKNOWN, |sp| Value::constant(sp + 8 + consumed));
                        state.cpu.pc = numeric.unwrap_or(0);
                        results.push(Boundary::Host { state, target });
                        break;
                    }
                }
                if let Some(branch) = state
                    .step(&mut self.expressions, &self.image, &i)
                    .with_context(|| format!("lift VM case at {pc:#x}, step {}", state.cpu.step))?
                {
                    // Expose an x64 conditional as CFG edges immediately.
                    // Rejoining these states in Graph avoids enumerating every
                    // combination of the handler's opaque branch histories.
                    results.push(Boundary::Continue(state));
                    results.push(Boundary::Continue(branch));
                    break;
                }
            }
        }
        ensure!(!results.is_empty(), "VM case has no terminating boundary");
        Ok(results)
    }

    fn pointer(&mut self, address: u64) -> Id {
        let delta = self.expressions.constant(address.wrapping_sub(self.stack));
        let input = self.expressions.input(4);
        self.expressions
            .binary(iced_x86::Mnemonic::Add, input, delta, 64)
    }

    pub fn word(&mut self, state: &StateExpressions, address: u64) -> Result<Id> {
        let pointer = self.pointer(address);
        state.read(&mut self.expressions, &self.image, address, 8, pointer)
    }

    pub fn describe(&self, id: Id, depth: usize) -> String {
        if depth == 0 {
            return format!("%{id}");
        }
        match self.expressions.node(id) {
            Expr::Constant(value) => format!("{value:#x}"),
            Expr::Input(name) => format!("input{name}"),
            Expr::Cell(name) => format!("cell{name}"),
            Expr::Function(rva) => format!("function{rva:#x}"),
            Expr::ImageBase => "image_base".into(),
            Expr::GuestPointer(value) => format!("guest({})", self.describe(*value, depth - 1)),
            Expr::PrivateAddress(value) => format!("private{value:#x}"),
            Expr::Continuation(value) => format!("continuation{value:#x}"),
            Expr::RuntimeData(value) => format!("runtime_data{value:#x}"),
            Expr::Unary(op, value, width) => {
                format!("{op:?}{width}({})", self.describe(*value, depth - 1))
            }
            Expr::Binary(op, a, b, width) => format!(
                "{op:?}{width}({},{})",
                self.describe(*a, depth - 1),
                self.describe(*b, depth - 1)
            ),
            Expr::Extract(value, at, width) => {
                format!("bits({},{at},{width})", self.describe(*value, depth - 1))
            }
            Expr::Insert(a, b, at, width) => format!(
                "insert({},{},{at},{width})",
                self.describe(*a, depth - 1),
                self.describe(*b, depth - 1)
            ),
            Expr::Divide(a, b, c, width, signed, remainder) => format!(
                "divide{width}(high={},low={},divisor={},signed={signed},remainder={remainder})",
                self.describe(*a, depth - 1),
                self.describe(*b, depth - 1),
                self.describe(*c, depth - 1)
            ),
            Expr::Flags(op, a, b, _, width) => format!(
                "flags{op:?}{width}({},{})",
                self.describe(*a, depth - 1),
                self.describe(*b, depth - 1)
            ),
            Expr::Load(address, width, segment, _) => format!(
                "load{width}{segment:?}({})",
                self.describe(*address, depth - 1)
            ),
        }
    }
}
