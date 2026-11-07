//! x64 template metadata and conservative native startup recovery.
use super::static_x64::{self as cpu, Action, Image, State, Value};
use crate::common::{
    io::{take, u32_at, u64_at},
    pe::Pe,
};
use anyhow::{Context, Result, bail, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic as M, OpKind, Register as R};
use std::collections::HashMap;

pub(crate) struct Runtime<'a> {
    pub records: Vec<&'a [u8]>,
    pub streams: Vec<(u32, u32, usize)>,
    handlers: HashMap<u32, Vec<u8>>,
    patch: [u32; 12],
    dispatcher: Vec<u8>,
}
impl<'a> Runtime<'a> {
    pub fn parse(image: &'a [u8]) -> Result<Self> {
        let pe = Pe::parse(image)?;
        ensure!(pe.is_64, "expected x64 runtime");
        let mut header = None;
        for i in Decoder::with_ip(
            64,
            take(image, pe.entry as usize, 48)?,
            pe.entry as u64,
            DecoderOptions::NONE,
        ) {
            if i.mnemonic() == M::Mov
                && i.op0_register() == R::R8
                && matches!(i.op1_kind(), OpKind::Immediate32to64 | OpKind::Immediate64)
            {
                header = Some(i.immediate(1) as usize);
            }
            if i.mnemonic() == M::Call {
                break;
            }
        }
        let header = header.context("x64 runtime header argument missing")?;
        let table = u32_at(image, header + 4)? as usize;
        ensure!(
            table < header && (header - table).is_multiple_of(4),
            "invalid x64 token table"
        );
        let count = (header - table) / 4;
        ensure!(count <= 1_000_000, "oversized x64 token table");
        let mut records = Vec::new();
        for index in 0..count {
            records.push(take(image, u32_at(image, table + index * 4)? as usize, 88)?);
        }
        let start = u32_at(image, header + 8)? as usize;
        let end = start
            .checked_add(4)
            .and_then(|v| v.checked_add(u32_at(image, start).ok()? as usize))
            .context("x64 template extent overflow")?;
        take(image, start, end - start)?;
        let count = u32_at(image, start + 4)? as usize;
        ensure!((1..=65536).contains(&count), "invalid x64 stream count");
        let mut at = start + 12;
        let mut streams = Vec::new();
        for _ in 0..count {
            let rva = u32_at(image, at)?;
            let n = u32_at(image, at + 4)? as usize;
            at += 8;
            take(image, at, n)?;
            streams.push((rva, u32::try_from(at)?, n));
            at += n;
        }
        ensure!(
            at - start - 12 == u32_at(image, start + 8)? as usize,
            "x64 stream size mismatch"
        );
        let count = u32_at(image, at)? as usize;
        at += 4;
        ensure!(count <= 65536, "too many x64 handlers");
        let mut handlers = HashMap::new();
        for _ in 0..count {
            let id = u32_at(image, at)?;
            let n = u32_at(image, at + 4)? as usize;
            at += 8;
            ensure!(
                handlers.insert(id, take(image, at, n)?.to_vec()).is_none(),
                "duplicate x64 handler"
            );
            at += n;
        }
        let mut patch = [0; 12];
        for (i, v) in patch.iter_mut().enumerate() {
            *v = u32_at(image, at + i * 4)?;
        }
        at += 48;
        ensure!(
            at + patch[11] as usize == end && patch[11] <= 0x10000,
            "invalid x64 dispatcher extent"
        );
        let dispatcher = take(image, at, patch[11] as usize)?.to_vec();
        for &at in &patch[..9] {
            ensure!(
                u64_at(&dispatcher, at as usize)? == 0xc0dec0dec0dec0de,
                "unexpected x64 dispatcher patch"
            );
        }
        ensure!(
            patch[9] < patch[11] && patch[10] < patch[11],
            "invalid x64 dispatcher entry"
        );
        Ok(Self {
            records,
            streams,
            handlers,
            patch,
            dispatcher,
        })
    }
}

const LOADER: u64 = 0x180000000;
const DISPATCH: u64 = 0x190000000;
const HEAP: u64 = 0x191000000;
const CONTEXT: u64 = 0x1a0000000;
const CALLBACKS: u64 = 0x1b0000000;
const STACK: u64 = 0x200100000;

struct Machine<'a> {
    runtime: Runtime<'a>,
    image: Image,
    base: u64,
    host_end: u32,
    cursor: u64,
    cases: HashMap<u32, (u64, u64)>,
    thunks: HashMap<u64, u64>,
}
impl Machine<'_> {
    fn allocate(&mut self, bytes: Vec<u8>) -> Result<u64> {
        let at = self.cursor;
        self.cursor = (at + bytes.len() as u64 + 15) & !15;
        ensure!(
            self.cursor < HEAP + 0x1000000,
            "x64 template arena exhausted"
        );
        self.image.add(at, bytes)?;
        Ok(at)
    }
    fn thunk(&mut self, source: u64) -> Result<u64> {
        if let Some(&at) = self.thunks.get(&source) {
            return Ok(at);
        }
        ensure!(
            self.runtime
                .streams
                .iter()
                .any(
                    |&(_, at, n)| (LOADER + at as u64..LOADER + at as u64 + n as u64)
                        .contains(&source)
                ),
            "x64 continuation outside bytecode"
        );
        let mut code = vec![0x6a, 0, 0xff, 0x35, 6, 0, 0, 0, 0xff, 0x25, 8, 0, 0, 0];
        code.extend(source.to_le_bytes());
        code.extend((DISPATCH + self.runtime.patch[9] as u64).to_le_bytes());
        let at = self.allocate(code)?;
        self.thunks.insert(source, at);
        Ok(at)
    }
    fn advance(&mut self, mut state: State) -> Result<State> {
        for step in 0..10000 {
            state.step = step;
            let mut stopped = Vec::new();
            let base = self.base;
            let host_end = self.host_end;
            cpu::analyze(&mut self.image, state, |image, s| {
                if (base..base + host_end as u64).contains(&s.pc)
                    || (CALLBACKS..CALLBACKS + 144).contains(&s.pc)
                {
                    stopped.push(s.clone());
                    return Ok(Action::Finish);
                }
                let i = image.instruction(s.pc)?;
                ensure!(
                    (STACK - 0x10000..STACK + 0x1000).contains(&s.esp()?),
                    "x64 VM stack escapes analysis frame"
                );
                if (i.op0_kind() == OpKind::Memory
                    || (i.mnemonic() == M::Xchg && i.op1_kind() == OpKind::Memory))
                    && i.mnemonic() != M::Cmp
                    && i.mnemonic() != M::Test
                    && i.mnemonic() != M::Push
                    && i.mnemonic() != M::Call
                    && i.mnemonic() != M::Jmp
                {
                    let at = cpu::address(s, &i)?.require("x64 template store")?;
                    ensure!(
                        (STACK - 0x10000..STACK + 0x1000).contains(&at),
                        "x64 startup writes outside its stack: {at:#x}"
                    );
                }
                Ok(Action::Decode)
            })?;
            state = stopped
                .pop()
                .context("x64 startup did not reach a boundary")?;
            for other in stopped {
                ensure!(
                    state.pc == other.pc && state.esp()? == other.esp()?,
                    "ambiguous x64 startup boundary"
                );
                state.join(&other, &self.image);
            }
            if (base..base + host_end as u64).contains(&state.pc) {
                return Ok(state);
            }
            ensure!(
                (state.pc - CALLBACKS).is_multiple_of(16),
                "invalid x64 VM callback"
            );
            let index = (state.pc - CALLBACKS) / 16;
            let arg = |n: u64| {
                state
                    .read(&self.image, state.esp().unwrap() + 0x28 + n * 8, 8)
                    .require("x64 VM callback argument")
            };
            let value = match index {
                0 => {
                    let source = arg(0)?;
                    self.thunk(source)?
                }
                1 => CONTEXT,
                2 => base,
                4 => {
                    let source = arg(0)?;
                    self.runtime
                        .streams
                        .iter()
                        .find(|s| base + s.0 as u64 == source)
                        .map_or(0, |s| LOADER + s.1 as u64)
                }
                5 => {
                    let source = arg(0)?;
                    self.runtime
                        .streams
                        .iter()
                        .map(|s| LOADER + s.1 as u64)
                        .filter(|&p| p < source)
                        .max()
                        .unwrap_or(0)
                }
                7 => {
                    let id = u32::try_from(arg(0)?)?;
                    let tail = arg(1)?;
                    ensure!(
                        tail == DISPATCH + self.runtime.patch[10] as u64,
                        "unexpected x64 handler continuation"
                    );
                    if let Some(&(at, old)) = self.cases.get(&id) {
                        ensure!(old == tail, "x64 case cache mismatch");
                        at
                    } else {
                        let mut bytes = self
                            .runtime
                            .handlers
                            .get(&id)
                            .with_context(|| format!("unknown x64 VM case {id:#x}"))?
                            .clone();
                        let delta = i32::try_from(
                            tail as i64 - (self.cursor + bytes.len() as u64 + 5) as i64,
                        )?;
                        bytes.push(0xe9);
                        bytes.extend(delta.to_le_bytes());
                        let at = self.allocate(bytes)?;
                        self.cases.insert(id, (at, tail));
                        at
                    }
                }
                8 => {
                    let source = arg(0)?;
                    let dest = arg(1)?;
                    let size = arg(2)?;
                    ensure!(
                        size <= 0x10000 && dest >= STACK - 0x10000 && dest + size <= STACK + 0x1000,
                        "x64 VM copy outside stack"
                    );
                    for n in 0..size {
                        let v = state.read(&self.image, source + n, 1);
                        state.write(&self.image, dest + n, 1, v);
                    }
                    dest
                }
                _ => bail!("unsupported x64 VM callback {index}"),
            };
            state.return_from(&self.image, 0)?;
            state.registers[0] = Value::constant(value);
            for r in [1, 2, 8, 9, 10, 11] {
                state.registers[r] = Value::UNKNOWN;
            }
            state.flags = Value::unknown_flags();
            // These callbacks use the VM's stack ABI; the verified templates
            // do not take arguments in the Windows volatile registers.
        }
        bail!("x64 startup VM step limit")
    }
}

/// Prove a startup bridge has no guest effects beyond one call and a stack
/// adjustment/tail transfer. Any more complex guest behavior is rejected.
pub fn startup(
    loader: &[u8],
    base: u64,
    host_end: u32,
    entry: u32,
    output_rva: u32,
) -> Result<Vec<u8>> {
    let runtime = Runtime::parse(loader)?;
    ensure!(
        runtime
            .streams
            .iter()
            .filter(|s| s.0 < host_end)
            .map(|s| s.0)
            .collect::<Vec<_>>()
            == [entry],
        "unsupported x64 host VM roots"
    );
    let mut image = Image::default();
    image.add(LOADER, loader.to_vec())?;
    image.zero(CONTEXT, 0x10000);
    let mut dispatcher = runtime.dispatcher.clone();
    for (i, &at) in runtime.patch[..9].iter().enumerate() {
        let v = if i == 3 {
            DISPATCH
        } else if i == 6 {
            DISPATCH + runtime.patch[10] as u64
        } else {
            CALLBACKS + i as u64 * 16
        };
        dispatcher[at as usize..at as usize + 8].copy_from_slice(&v.to_le_bytes());
    }
    image.add(DISPATCH, dispatcher)?;
    let mut machine = Machine {
        runtime,
        image,
        base,
        host_end,
        cursor: HEAP,
        cases: HashMap::new(),
        thunks: HashMap::new(),
    };
    let mut initial = State::new(DISPATCH, STACK);
    initial.write(
        &machine.image,
        STACK,
        8,
        Value::constant(base + entry as u64 + 5),
    );
    let first = machine.advance(initial.clone())?;
    for r in 0..16 {
        ensure!(
            first.registers[r] == initial.registers[r],
            "x64 startup changes register {r}"
        );
    }
    ensure!(
        first.flags == initial.flags,
        "x64 startup changes flags before its call"
    );
    let continuation = first
        .read(&machine.image, STACK, 8)
        .require("x64 host return continuation")?;
    ensure!(
        machine.thunks.values().any(|&v| v == continuation),
        "x64 call has no VM continuation"
    );
    let after_call = State::new(continuation, STACK + 8);
    let second = machine.advance(after_call.clone())?;
    for r in 0..16 {
        if r != 4 {
            ensure!(
                second.registers[r] == after_call.registers[r],
                "x64 continuation changes register {r}"
            );
        }
    }
    let delta = second
        .esp()?
        .checked_sub(STACK + 8)
        .context("x64 continuation grows stack")?;
    ensure!(delta <= 0x10000, "x64 continuation stack delta too large");
    for state in [&first, &second] {
        let low = if state.pc == first.pc {
            STACK + 8
        } else {
            second.esp()?
        };
        ensure!(
            state.live_memory(low).is_empty(),
            "x64 startup modifies live caller stack"
        );
    }
    let mut expected = after_call.clone();
    let mut add = vec![0x48, 0x81, 0xc4];
    add.extend(u32::try_from(delta)?.to_le_bytes());
    let instruction = Decoder::new(64, &add, DecoderOptions::NONE).decode();
    if delta != 0 {
        cpu::execute(&mut expected, &machine.image, &instruction)?;
    }
    ensure!(
        second.flags == expected.flags,
        "x64 continuation flags differ from stack adjustment: {:?} != {:?}",
        second.flags,
        expected.flags
    );
    let mut code = Vec::new();
    code.push(0xe8);
    code.extend(
        i32::try_from(first.pc as i64 - (base + output_rva as u64 + 5) as i64)?.to_le_bytes(),
    );
    if delta != 0 {
        if delta <= 127 {
            code.extend([0x48, 0x83, 0xc4, delta as u8]);
        } else {
            code.extend([0x48, 0x81, 0xc4]);
            code.extend(u32::try_from(delta)?.to_le_bytes());
        }
    }
    code.push(0xe9);
    code.extend(
        i32::try_from(
            second.pc as i64 - (base + output_rva as u64 + code.len() as u64 + 4) as i64,
        )?
        .to_le_bytes(),
    );
    eprintln!(
        "Devirtualized x64 startup: call {:#x}, stack +{delta:#x}, jump {:#x}",
        first.pc - base,
        second.pc - base
    );
    Ok(code)
}

impl Runtime<'_> {
    pub fn projection(&self, image: &[u8]) -> Result<Vec<(usize, usize)>> {
        let mut groups: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut last = None;
        for index in 5..self.records.len() {
            let raw = self.records[index];
            if u32_at(raw, 0)? != 0x60 || u32_at(raw, 16)? != 0x90 {
                continue;
            }
            let target = u64_at(raw, 32)?;
            if target >> 32 != 1 {
                continue;
            }
            let at = (target as u32) as usize;
            let Some(code) = image.get(at..at + 40) else {
                continue;
            };
            let decoded = Decoder::new(64, code, DecoderOptions::NONE)
                .into_iter()
                .collect::<Vec<_>>();
            if !decoded.windows(2).any(|w| {
                w[0].mnemonic() == M::Mov
                    && w[0].op0_register() == R::RAX
                    && w[0].op1_register() == R::RCX
                    && w[1].mnemonic() == M::Mov
                    && w[1].op0_register() == R::RCX
                    && w[1].op1_register() == R::RDX
            }) {
                continue;
            }
            let size = self.records[index - 5];
            let dest = self.records[index - 3];
            let len = self.records[index - 2];
            let src = self.records[index - 1];
            if u32_at(size, 0)? != 0x52
                || u32_at(size, 16)? != 0x8d
                || u32_at(size, 20)? != 0x3a
                || u32_at(size, 40)? != 0x8f
                || u32_at(dest, 0)? != 0x51
                || u32_at(dest, 16)? != 0x8c
                || u32_at(dest, 20)? != 0x36
                || u32_at(dest, 40)? != 0x8d
                || u32_at(dest, 44)? != 0x35
                || u32_at(len, 0)? != 0x52
                || u32_at(len, 20)? != 0x2d
                || u32_at(len, 40)? != 0x8d
                || u64_at(len, 56)? != u64_at(size, 32)?
                || u32_at(src, 0)? != 0x52
                || u32_at(src, 20)? != 0x37
                || u32_at(src, 40)? != 0x8d
                || u32_at(src, 44)? != 0x3a
            {
                continue;
            }
            let size = u64_at(size, 56)? as usize;
            let dest = u64_at(dest, 56)? as usize;
            if !(8..=0x100000).contains(&size) || dest == 0 || dest + size > 0x100000 {
                continue;
            }
            if last != Some(index - 8) {
                groups.push(Vec::new());
            }
            groups.last_mut().unwrap().push((dest, size));
            last = Some(index);
        }
        groups.retain(|g| {
            g.len() >= 3
                && g.last().unwrap().1 > 0x1000
                && g.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0)
        });
        ensure!(
            groups.len() == 1,
            "ambiguous x64 config projection: {}",
            groups.len()
        );
        Ok(groups.pop().unwrap())
    }
}

impl Runtime<'_> {
    pub fn hooks(&self, image: &[u8]) -> Result<HashMap<u32, (String, String)>> {
        let mut registries = Vec::new();
        let global = |r: &[u8]| -> Result<Option<u32>> {
            Ok((u32_at(r, 0)? == 0x51
                && u32_at(r, 40)? == 0x8d
                && u32_at(r, 44)? == 0
                && u32_at(r, 48)? == 0
                && u32_at(r, 52)? & 1 != 0)
                .then(|| u64_at(r, 56).ok().and_then(|v| u32::try_from(v).ok()))
                .flatten())
        };
        for index in 1..self.records.len().saturating_sub(16) {
            let shift = self.records[index - 1];
            if u32_at(shift, 0)? != 0x28
                || u32_at(shift, 20)? != 0x35
                || u32_at(shift, 40)? != 0x8f
                || u64_at(shift, 56)? != 4
            {
                continue;
            }
            let Some(names) = global(self.records[index])? else {
                continue;
            };
            let mut stride = None;
            let mut hooks = None;
            for r in &self.records[index + 1..index + 16] {
                if u32_at(r, 0)? == 9
                    && u32_at(r, 20)? == 0x37
                    && u32_at(r, 44)? == 0x35
                    && u32_at(r, 64)? == 0x8f
                {
                    stride = Some(u64_at(r, 80)? as usize);
                }
                if stride.is_some()
                    && let Some(at) = global(r)?
                {
                    hooks = Some(at);
                }
                if u32_at(r, 0)? == 0x50
                    && u32_at(r, 16)? == 0x8d
                    && u32_at(r, 20)? == 0x3a
                    && u32_at(r, 40)? == 0x8f
                    && let (Some(stride), Some(hooks)) = (stride, hooks)
                {
                    let count = usize::try_from(u64_at(r, 56)?)?
                        .checked_add(1)
                        .context("hook count overflow")?;
                    if (1..=1024).contains(&count)
                        && (8..=1024).contains(&stride)
                        && stride.is_multiple_of(8)
                    {
                        registries.push((names, hooks, stride, count));
                    }
                    break;
                }
            }
        }
        registries.sort_unstable();
        registries.dedup();
        ensure!(registries.len() == 1, "cannot derive x64 API registry");
        let (names, hooks, stride, count) = registries[0];
        let base = Pe::parse(image)?.image_base;
        take(image, names as usize, count * 16)?;
        take(image, hooks as usize, count * stride)?;
        let string = |pointer: u64| -> Result<String> {
            let at = usize::try_from(
                pointer
                    .checked_sub(base)
                    .context("API string below runtime")?,
            )?;
            let data = image.get(at..).context("API string outside runtime")?;
            let end = data
                .iter()
                .take(1024)
                .position(|&b| b == 0)
                .context("unterminated API string")?;
            ensure!(
                end != 0 && data[..end].iter().all(|b| (32..127).contains(b)),
                "invalid API registry string"
            );
            Ok(String::from_utf8(data[..end].to_vec())?)
        };
        let mut columns = Vec::new();
        for offset in (0..stride).step_by(8) {
            let mut targets = Vec::new();
            for index in 0..count {
                let pointer = u64_at(image, hooks as usize + index * stride + offset)?;
                let Some(at) = pointer
                    .checked_sub(base)
                    .and_then(|v| usize::try_from(v).ok())
                else {
                    break;
                };
                let Some(code) = image.get(at..at + 5) else {
                    break;
                };
                let i = Decoder::with_ip(64, code, at as u64, DecoderOptions::NONE).decode();
                if i.mnemonic() != M::Jmp
                    || i.op0_kind() != OpKind::NearBranch64
                    || i.near_branch64() >= image.len() as u64
                {
                    break;
                }
                targets.push(u32::try_from(at)?);
            }
            if targets.len() == count {
                columns.push(targets);
            }
        }
        ensure!(
            columns.len() == 1,
            "ambiguous x64 API registry target column"
        );
        let mut result = HashMap::new();
        for (index, target) in columns.pop().unwrap().into_iter().enumerate() {
            result.insert(
                target,
                (
                    string(u64_at(image, names as usize + index * 16)?)?,
                    string(u64_at(image, names as usize + index * 16 + 8)?)?,
                ),
            );
        }
        Ok(result)
    }
}

impl Runtime<'_> {
    /// Find the context flag guarding a digest appended to the section key.
    pub fn section_suffix(&self) -> Result<usize> {
        let mut found = Vec::new();
        for index in 1..self.records.len().saturating_sub(3) {
            let load = self.records[index - 1];
            let compare = self.records[index];
            let branch = self.records[index + 1];
            if u32_at(load, 0)? != 0x52
                || u32_at(load, 20)? != 0x35
                || u32_at(load, 40)? != 0x8d
                || u32_at(load, 44)? != 0
                || u32_at(load, 52)? & 1 == 0
                || u32_at(compare, 0)? != 0x50
                || u32_at(compare, 16)? != 0x8d
                || u32_at(compare, 20)? != 0x35
                || u32_at(compare, 24)? != 0
                || (u32_at(compare, 28)? >> 8) & 255 != 8
                || u32_at(compare, 40)? != 0x8f
                || u64_at(compare, 56)? != 0
                || u32_at(branch, 0)? != 0x2c
                || u32_at(branch, 16)? != 0x90
                || u32_at(self.records[index + 2], 0)? != 0x232
            {
                continue;
            }
            let end = usize::try_from(u64_at(branch, 32)?)?;
            if end <= index + 12 || end > self.records.len() || end - index > 128 {
                continue;
            }
            let append = self.records[end - 2];
            let length = self.records[end - 4];
            let source = self.records[end - 5];
            if u32_at(append, 0)? != 0x4d
                || u32_at(append, 16)? != 0x8d
                || u32_at(append, 20)? != 0x3a
                || u32_at(append, 40)? != 0x8f
                || u64_at(append, 56)? != 16
                || u32_at(length, 0)? != 0x52
                || u32_at(length, 20)? != 0x2d
                || u32_at(length, 40)? != 0x8f
                || u64_at(length, 56)? != 16
                || u32_at(source, 0)? != 0x51
                || u32_at(source, 20)? != 0x37
                || u32_at(source, 40)? != 0x8d
                || u32_at(source, 44)? != 0x3a
                || u32_at(self.records[end - 3], 0)? != 0x60
            {
                continue;
            }
            let digest = self.records[index + 3..end - 5].iter().any(|raw| {
                u32_at(raw, 0).ok() == Some(0x51)
                    && u32_at(raw, 20).ok() == Some(0x3d)
                    && u32_at(raw, 40).ok() == Some(0x8d)
                    && u32_at(raw, 44).ok() == Some(0x3a)
                    && u64_at(raw, 56).ok() == u64_at(source, 56).ok()
            });
            if digest {
                found.push(usize::try_from(u64_at(compare, 32)?)?);
            }
        }
        found.sort_unstable();
        found.dedup();
        ensure!(
            found.len() == 1,
            "cannot uniquely derive x64 machine-dependent section key guard"
        );
        Ok(found[0])
    }
}
