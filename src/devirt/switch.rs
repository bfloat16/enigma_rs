//! Specialize a switch VM using its serialized cases and input bytecode.
use super::{
    graph::Start,
    ir::{Expr, Expressions, Id},
    lift::StateExpressions,
    static_x86::{Image, State, Value},
    vm::Profile,
};
use crate::common::io::u32_at;
use anyhow::{Context, Result, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub(crate) enum Boundary {
    Continue(StateExpressions),
    Case {
        id: u32,
        continuation: u32,
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
    pub base: u32,
    pub loader_base: u32,
    pub dispatch: u32,
    pub heap: u32,
    pub context: u32,
    pub stack: u32,
    pub stop: u32,
    pub callbacks: u32,
    entry: u32,
    entry_size: u32,
    decoder: u32,
    trampoline: u32,
    pub initial: StateExpressions,
    cursor: u32,
    compiled: HashMap<u32, (u32, u32)>,
    trampolines: HashMap<u32, u32>,
    pub minimum_stack: u32,
    pub guest_layout: Option<[u32; 9]>,
    pc_scores: HashMap<u32, usize>,
    raw_start: Option<u32>,
}

fn aligned(value: u32, size: u32) -> Result<u32> {
    Ok(value
        .checked_add(size - 1)
        .context("analysis address overflow")?
        & !(size - 1))
}

impl Session {
    // Conservatively retain any value that could name loader code, bytecode,
    // callbacks or the private operand frame. Ordinary scalar constants may
    // join, but these values must remain available to decode the next case.
    pub fn analysis_pointer(&self, value: u32) -> bool {
        (self.loader_base..self.dispatch).contains(&value)
            || (self.dispatch..self.stop.saturating_add(0x2000)).contains(&value)
    }
    #[cfg(test)]
    pub fn synthetic_program(bytes: Vec<u8>) -> Self {
        let mut session = Self::synthetic(Expressions::default());
        session.entry = 0x1000;
        session.entry_size = bytes.len() as u32;
        session.loader_base = 0x1fff0000;
        session.dispatch = 0x20000000;
        session.decoder = session.dispatch + 0x100;
        session.stop = session.stack + 0x20000;
        session.callbacks = session.stop + 16;
        session.image.add(session.entry, bytes).unwrap();
        session.initial.guest_sp = Some(session.stack + 0x100);
        session.initial.cpu.write(
            &session.image,
            session.stack,
            4,
            Value::constant(session.stop),
        );
        let target = session.expressions.constant(session.stop);
        session
            .initial
            .write(&mut session.expressions, session.stack, 4, target);
        session
    }
    pub fn fixed_host_header(&mut self, header: &[u8]) -> Result<()> {
        if header.is_empty() {
            return Ok(());
        }
        let nt = u32_at(header, 0x3c)?;
        let optional = nt + 24;
        let mut bytes = HashMap::new();
        // These fields survive PE reconstruction and are mapped read-only.
        // Do not specialize section counts, OEP, SizeOfImage or the new IAT.
        for (offset, length) in [
            (0, 2),
            (0x3c, 4),
            (nt, 4),
            (nt + 4, 2),
            (optional, 2),
            (optional + 92, 4),
            (optional + 96 + 14 * 8, 8),
        ] {
            if offset == optional + 96 + 14 * 8
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
    #[cfg(test)]
    pub fn synthetic(mut expressions: Expressions) -> Self {
        let stack = 0x20080000;
        let initial = StateExpressions::new(
            State::new(0x1000, stack),
            &mut expressions,
            stack - 0x10000,
            stack + 0x10000,
        );
        Self {
            budget: super::budget::Budget::new().unwrap(),
            expressions,
            image: Image::default(),
            profile: Arc::new(Profile {
                base: 0x400000,
                trampoline: 0,
                decoder: 0,
                streams: Vec::new(),
                handlers: HashMap::new(),
                patch: [0; 12],
                dispatcher: Vec::new(),
            }),
            base: 0x400000,
            loader_base: 0x400000,
            dispatch: 0,
            heap: 0,
            context: 0,
            stack,
            stop: 0,
            callbacks: 0,
            entry: 0,
            entry_size: 0,
            decoder: 0,
            trampoline: 0,
            initial,
            cursor: 0,
            compiled: HashMap::new(),
            trampolines: HashMap::new(),
            minimum_stack: stack,
            guest_layout: None,
            pc_scores: HashMap::new(),
            raw_start: None,
        }
    }
    pub fn from_start(
        loader: &[u8],
        profile: Arc<Profile>,
        start: Start,
        entry: u32,
        budget: super::budget::Budget,
    ) -> Result<Self> {
        let base = profile.base;
        let (entry, continuation, raw_start) = match start {
            Start::Function(rva) => (rva, None, None),
            Start::Continuation(at) => (entry, Some(at), None),
            Start::Code(at) => {
                let source = profile
                    .streams
                    .iter()
                    .find(|s| (s.1..s.1 + s.2 as u32).contains(&at))
                    .context("native bytecode entry is outside streams")?
                    .0;
                (source, None, Some(at))
            }
        };
        ensure!(
            profile.streams.iter().any(|s| s.0 == entry),
            "no VM stream for entry {entry:#x}"
        );
        let loader_size = u32::try_from(loader.len())?;
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
        image.zero(context, 0x10000);
        let mut dispatcher = profile.dispatcher.clone();
        for (index, &at) in profile.patch[..9].iter().enumerate() {
            let value = match index {
                3 => dispatch,
                6 => dispatch + profile.patch[10],
                _ => callbacks + index as u32 * 16,
            };
            dispatcher[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
        }
        image.add(dispatch, dispatcher)?;
        let trampoline = profile.trampoline;
        let mut trampoline_code = vec![0xe9];
        trampoline_code.extend(dispatch.wrapping_sub(trampoline + 5).to_le_bytes());
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
                    .any(|s| (s.1..s.1 + s.2 as u32).contains(&offset)),
                "VM continuation outside streams"
            );
            let mut code = vec![0x68];
            code.extend(0u32.to_le_bytes());
            code.push(0x68);
            code.extend(source.to_le_bytes());
            code.push(0x68);
            code.extend((dispatch + profile.patch[9]).to_le_bytes());
            code.push(0xc3);
            code
        } else {
            let mut code = vec![0xe8];
            code.extend(trampoline.wrapping_sub(base + entry + 5).to_le_bytes());
            code
        };
        let entry_size = code.len() as u32;
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
            .map(|s| (loader_base + s.1, s.2 as u32, loader_base))
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
            compiled: HashMap::new(),
            trampolines: HashMap::new(),
            minimum_stack: stack,
            guest_layout: None,
            pc_scores: HashMap::new(),
            raw_start,
        })
    }

    fn allocate(&mut self, bytes: Vec<u8>) -> Result<u32> {
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

    fn argument(&mut self, state: &StateExpressions, index: u32) -> Result<u32> {
        state
            .cpu
            .read(&self.image, state.cpu.esp()? + 4 + index * 4, 4)
            .require("VM callback argument")
    }
    fn argument_expr(&mut self, state: &StateExpressions, index: u32) -> Result<Id> {
        let address = state.cpu.esp()? + 4 + index * 4;
        let pointer = self.expressions.intern(Expr::PrivateAddress(address));
        Ok(state.read(&mut self.expressions, &self.image, address, 4, pointer))
    }

    fn callback_return(
        &mut self,
        state: &mut StateExpressions,
        value: Value,
        consumed: u32,
    ) -> Result<()> {
        state.cpu.return_from(&self.image, consumed)?;
        state.cpu.registers[0] = value;
        state.cpu.registers[1] = Value::UNKNOWN;
        state.cpu.registers[2] = Value::UNKNOWN;
        // These stdcall callbacks clobber arithmetic flags, while the VM's
        // control flags remain those of its saved native register image.
        let mut flags = Value::unknown_flags();
        flags.bits |= state.cpu.flags.bits & !0x8d5;
        flags.known |= state.cpu.flags.known & !0x8d5;
        state.cpu.flags = flags;
        let amount = self.expressions.constant(4 + consumed);
        state.registers[4] =
            self.expressions
                .binary(iced_x86::Mnemonic::Add, state.registers[4], amount, 32);
        state.registers[0] = if let Some(value) = value.get() {
            self.expressions.constant(value)
        } else {
            self.expressions.fresh_input()
        };
        state.registers[1] = self.expressions.fresh_input();
        state.registers[2] = self.expressions.fresh_input();
        let preserved = self.expressions.constant(!0x8d5);
        let preserved =
            self.expressions
                .binary(iced_x86::Mnemonic::And, state.flags, preserved, 32);
        let unknown = self.expressions.fresh_input();
        let mask = self.expressions.constant(0x8d5);
        let written = self
            .expressions
            .binary(iced_x86::Mnemonic::And, unknown, mask, 32);
        state.flags = self
            .expressions
            .binary(iced_x86::Mnemonic::Or, preserved, written, 32);
        Ok(())
    }

    pub fn enter_case(
        &mut self,
        mut state: StateExpressions,
        id: u32,
        continuation: u32,
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
            let delta = continuation.wrapping_sub(self.cursor + bytes.len() as u32 + 5);
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
        let mut offsets = [None; 9];
        for offset in (0..span).step_by(4) {
            let value = self.word(state, frame + offset);
            if state.initializer_words.get(&(frame + offset)) == Some(&value) {
                continue;
            }
            if let Expr::Input(register) = *self.expressions.node(value)
                && register <= 8
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
                offset.context("VM initializer did not expose all x86 registers and flags")
            })
            .collect::<Result<Vec<_>>>()?;
        let layout: [u32; 9] = layout.try_into().unwrap();
        let sp = self.word(state, frame + layout[4]);
        let sp = self.expressions.intern(Expr::GuestPointer(sp));
        state.write(&mut self.expressions, frame + layout[4], 4, sp);
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
        let mut visited = HashSet::new();
        let mut seen_pc = HashSet::new();
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
                    if state.cpu.step == 1
                        && let Some(at) = self.raw_start.take()
                    {
                        self.activate(&mut state)?;
                        let frame = state.cpu.registers[5].require("VM frame")?;
                        let offset = *self
                            .pc_scores
                            .iter()
                            .max_by_key(|(_, score)| *score)
                            .context("VM decoder exposes no instruction cursor")?
                            .0;
                        let pointer = self.loader_base + at;
                        state
                            .cpu
                            .write(&self.image, frame + offset, 4, Value::constant(pointer));
                        let pointer = self.expressions.intern(Expr::PrivateAddress(pointer));
                        state.write(&mut self.expressions, frame + offset, 4, pointer);
                    }
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
                        let numeric = state.cpu.read(&self.image, frame + offset, 4).get();
                        if numeric.is_none() {
                            let target = self.word(&state, frame + offset);
                            bail!(
                                "VM bytecode cursor is unproven at step {}, frame offset {offset:#x}: {}",
                                state.cpu.step,
                                self.describe(target, 8)
                            );
                        } else if let Some(pointer) = numeric
                            && self.profile.streams.iter().any(|s| {
                                (self.loader_base + s.1..self.loader_base + s.1 + s.2 as u32)
                                    .contains(&pointer)
                            })
                        {
                            let value = self.expressions.intern(Expr::PrivateAddress(pointer));
                            state.write(&mut self.expressions, frame + offset, 4, value);
                        }
                    }
                    if let Some(pointer) = state.cpu.registers[0].get() {
                        let relative = pointer.wrapping_sub(self.base);
                        if self
                            .profile
                            .streams
                            .iter()
                            .any(|s| (s.1..s.1 + s.2 as u32).contains(&relative))
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
                                let mut bytes = vec![0x68];
                                bytes.extend(0u32.to_le_bytes());
                                bytes.push(0x68);
                                bytes.extend(source.to_le_bytes());
                                bytes.push(0x68);
                                bytes.extend((self.dispatch + self.profile.patch[9]).to_le_bytes());
                                bytes.push(0xc3);
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
                                    (source.wrapping_sub(p) as i32) > 0
                                        && source.wrapping_sub(p) < i32::MAX as u32
                                })
                                .min_by_key(|&p| source.wrapping_sub(p))
                                .unwrap_or(0);
                            (Value::constant(target), 4)
                        }
                        8 => {
                            let source_expr = self.argument_expr(&state, 0)?;
                            let source = state.cpu.read(&self.image, state.cpu.esp()? + 4, 4).get();
                            let target_expr = self.argument_expr(&state, 1)?;
                            let target = state.cpu.read(&self.image, state.cpu.esp()? + 8, 4).get();
                            let size = (self.argument(&state, 2)? as i32).max(0) as u32;
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
                                    32,
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
                                        ),
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
                                        32,
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
                            .any(|s| (s.1..s.1 + s.2 as u32).contains(&offset))
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
                    || (self.dispatch..self.dispatch + self.profile.dispatcher.len() as u32)
                        .contains(&pc)
                    || (self.heap..self.cursor).contains(&pc);
                if !internal {
                    let target = self.expressions.constant(pc);
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
                if (self.dispatch..self.dispatch + self.profile.dispatcher.len() as u32)
                    .contains(&pc)
                    && i.mnemonic() == iced_x86::Mnemonic::Mov
                    && i.op1_kind() == iced_x86::OpKind::Memory
                    && i.memory_base() == iced_x86::Register::EBP
                {
                    let value = super::static_x86::operand(&state.cpu, &self.image, &i, 1)?;
                    if let Some(pointer) = value.get()
                        && self.profile.streams.iter().any(|s| {
                            (self.loader_base + s.1..self.loader_base + s.1 + s.2 as u32)
                                .contains(&pointer)
                        })
                    {
                        let at = super::static_x86::address(&state.cpu, &i)?
                            .require("VM control field")?;
                        let frame = state.cpu.registers[5].require("VM frame")?;
                        *self.pc_scores.entry(at.wrapping_sub(frame)).or_default() += 1;
                    }
                }
                if i.mnemonic() == iced_x86::Mnemonic::Ret {
                    let sp = state.registers[4];
                    let (target, value) = if self.expressions.guest_pointer(sp) {
                        state.guest_read(&mut self.expressions, sp, 4, iced_x86::Register::SS)
                    } else {
                        let esp = state.cpu.esp()?;
                        (self.word(&state, esp), state.cpu.read(&self.image, esp, 4))
                    };
                    let numeric = value.get();
                    let is_continuation = numeric
                        .is_some_and(|pc| self.trampolines.values().any(|&target| target == pc));
                    let within = !is_continuation
                        && numeric.is_some_and(|pc| {
                            pc == self.stop
                                || (self.dispatch
                                    ..self.dispatch + self.profile.dispatcher.len() as u32)
                                    .contains(&pc)
                                || (self.heap..self.cursor).contains(&pc)
                        });
                    if !within {
                        let consumed = if i.op_count() > 0 {
                            i.immediate16() as u32
                        } else {
                            0
                        };
                        let amount = self.expressions.constant(4 + consumed);
                        state.registers[4] = self.expressions.binary(
                            iced_x86::Mnemonic::Add,
                            state.registers[4],
                            amount,
                            32,
                        );
                        state.cpu.registers[4] = state.cpu.registers[4]
                            .get()
                            .map_or(Value::UNKNOWN, |sp| Value::constant(sp + 4 + consumed));
                        state.cpu.pc = numeric.unwrap_or(0);
                        results.push(Boundary::Host { state, target });
                        break;
                    }
                }
                if let Some(branch) = state
                    .step(&mut self.expressions, &self.image, &i)
                    .with_context(|| format!("lift VM case at {pc:#x}, step {}", state.cpu.step))?
                {
                    // Expose an x86 conditional as CFG edges immediately.
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

    fn pointer(&mut self, address: u32) -> Id {
        let delta = self.expressions.constant(address.wrapping_sub(self.stack));
        let input = self.expressions.input(4);
        self.expressions
            .binary(iced_x86::Mnemonic::Add, input, delta, 32)
    }

    pub fn word(&mut self, state: &StateExpressions, address: u32) -> Id {
        let pointer = self.pointer(address);
        state.read(&mut self.expressions, &self.image, address, 4, pointer)
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
            Expr::Bytecode(value) => format!("bytecode{value:#x}"),
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

#[cfg(test)]
#[path = "../../test/template_runtime.rs"]
mod tests;
