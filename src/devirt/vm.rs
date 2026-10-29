//! Static recovery of the Delphi token VM and serialized template VM.
//! No Loader instruction, target process or host API is executed.
use super::static_x86::{self, Action, Image, State, Value};
use crate::common::io::{take, u32_at};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use std::collections::HashMap;

pub const BASE: u32 = 0x400000;
const STATE: u32 = 0x12000000;
const STACK: u32 = 0x20080000;
const STOP: u32 = 0x30000000;

#[derive(Clone, Debug)]
pub struct EntryCipher {
    pub offset: usize,
    pub bias: u32,
    pub length: usize,
    pub digest: usize,
}

/// Configuration projection and offsets recovered from runtime consumers.
#[derive(Clone, Debug)]
pub struct Layout {
    pub copies: Vec<(usize, usize)>,
    pub data: usize,
    pub relocations: usize,
    pub entry: usize,
    pub entry_cipher: Option<EntryCipher>,
    pub tls: usize,
    pub machine_suffix: usize,
    pub trampoline: u32,
}
impl Layout {
    pub fn parse(image: &[u8]) -> Result<Self> {
        let bootstrap = super::loader::Bootstrap::parse(image)?;
        let tokens = Tokens::parse(image)?;
        let copies = tokens.projection()?;
        let machine_suffix = tokens.section_suffix()?;
        let (tls, relocations) = super::native_layout::derive(
            image,
            copies[0].0..copies[0].0 + copies[0].1,
            copies[1].0..copies[1].0 + copies[1].1,
        )?;
        let data = copies[0].0;
        let entry = copies[1].0;
        let entry_cipher = tokens.entry_cipher(data, entry, copies[1].0 + copies[1].1)?;
        // The EVB object projection is derived from the serialized
        // configuration image and its self-validating container header.
        Ok(Self {
            copies,
            data,
            entry,
            entry_cipher,
            tls,
            relocations,
            machine_suffix,
            trampoline: bootstrap.trampoline,
        })
    }
}

pub struct Tokens<'a> {
    pub dispatch: u32,
    pub key: u32,
    pub records: Vec<&'a [u8]>,
    pub serialized: usize,
    pub(super) image: &'a [u8],
}
impl<'a> Tokens<'a> {
    pub fn parse(image: &'a [u8]) -> Result<Self> {
        let bootstrap = super::loader::Bootstrap::parse(image)?;
        let header = bootstrap.header;
        let table = u32_at(image, header + 4)? as usize;
        ensure!(
            header > table && (header - table).is_multiple_of(4),
            "invalid VM token table"
        );
        let count = (header - table) / 4;
        ensure!(count <= 1_000_000, "oversized VM token table");
        let mut records = Vec::with_capacity(count);
        for i in 0..count {
            records.push(take(image, u32_at(image, table + i * 4)? as usize, 72)?);
        }
        Ok(Self {
            dispatch: bootstrap.dispatch,
            key: u32_at(image, header)?,
            records,
            serialized: u32_at(image, header + 8)? as usize,
            image,
        })
    }

    /// Analyze a variable-length 0x231 native callback with the interpreter's
    /// actual register-state / index / payload arguments. No native execution.
    pub(super) fn extension(&self, image: &mut Image, index: usize) -> Result<[Value; 8]> {
        self.extension_inputs(
            image,
            index,
            std::array::from_fn(|r| {
                if r == 4 {
                    Value::constant(STACK - 0x10000)
                } else {
                    Value::input(100 + r as u32)
                }
            }),
        )
    }
    pub(super) fn extension_inputs(
        &self,
        image: &mut Image,
        index: usize,
        inputs: [Value; 8],
    ) -> Result<[Value; 8]> {
        let s = self.extension_state(image, index, inputs)?;
        let mut result: Option<[Value; 8]> = None;
        static_x86::analyze(image, s, |im, s| {
            if s.pc != STOP {
                return Ok(Action::Decode);
            }
            ensure!(
                s.registers[0].get() == Some(index as u32 + 1),
                "extension is not a sequential config operation"
            );
            let registers = std::array::from_fn(|r| s.read(im, STATE + r as u32 * 4, 4));
            if let Some(previous) = result {
                ensure!(
                    previous == registers,
                    "ambiguous extension config operation"
                );
            }
            result = Some(registers);
            Ok(Action::Finish)
        })?;
        result.context("extension did not return")
    }

    fn extension_state(&self, image: &Image, index: usize, inputs: [Value; 8]) -> Result<State> {
        let raw = self.records[index];
        ensure!(u32_at(raw, 0)? == 0x231, "not a native token extension");
        // The Image uses the original Loader mapping; recover this record's
        // address through the entry table instead of treating payload as x86.
        let at = raw.as_ptr() as usize - self.image.as_ptr() as usize;
        let target = BASE
            .checked_add(u32_at(raw, 4)?)
            .context("extension target overflow")?;
        let mut s = State::new(target, STACK);
        s.exact_memory = true;
        let flags = if inputs.iter().all(|v| v.get().is_some()) {
            Value::constant(0x202)
        } else {
            Value::unknown_flags()
        };
        s.flags = flags;
        s.registers[0] = Value::constant(BASE);
        s.registers[1] = Value::constant(STATE);
        s.registers[2] = Value::constant(BASE);
        s.registers[3] = Value::constant(target);
        for (i, v) in [STOP, index as u32, BASE + at as u32 + 8]
            .into_iter()
            .enumerate()
        {
            s.write(image, STACK + i as u32 * 4, 4, Value::constant(v));
        }
        for (r, value) in inputs.into_iter().enumerate() {
            s.write(image, STATE + r as u32 * 4, 4, value);
        }
        s.write(image, STATE + 0x50, 4, flags);
        Ok(s)
    }

    /// Follow the callback until it dereferences one of the virtual register
    /// inputs. Internal interpreter state and native stack accesses are excluded.
    pub(super) fn extension_access(
        &self,
        image: &mut Image,
        index: usize,
    ) -> Result<Option<(usize, u32, u32)>> {
        let inputs = std::array::from_fn(|r| Value::constant(0x41080000 + r as u32 * 0x100000));
        let state = self.extension_state(image, index, inputs)?;
        let mut access = None;
        static_x86::analyze(image, state, |image, state| {
            if state.pc == STOP {
                return Ok(Action::Finish);
            }
            let i = image.instruction(state.pc)?;
            if i.mnemonic() != Mnemonic::Lea
                && (0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory)
                && let Some(address) = static_x86::address(state, &i)?.get()
                && (0x41000000..0x41800000).contains(&address)
            {
                let register = ((address - 0x41000000) / 0x100000) as usize;
                let found = (
                    register,
                    address.wrapping_sub(inputs[register].get().unwrap()),
                    i.memory_size().size() as u32,
                );
                ensure!(
                    access.is_none_or(|old| old == found),
                    "ambiguous extension memory operand"
                );
                access = Some(found);
                return Ok(Action::Finish);
            }
            Ok(Action::Decode)
        })?;
        Ok(access)
    }
}

pub(crate) struct Profile {
    pub base: u32,
    pub trampoline: u32,
    pub decoder: u32,
    pub streams: Vec<(u32, u32, usize)>,
    pub handlers: HashMap<u32, Vec<u8>>,
    pub patch: [u32; 12],
    pub dispatcher: Vec<u8>,
}
impl Profile {
    pub fn parse(tokens: &Tokens<'_>) -> Result<Self> {
        let image = tokens.image;
        let at = tokens.serialized;
        let end = at
            .checked_add(4)
            .and_then(|v| v.checked_add(u32_at(image, at).ok()? as usize))
            .context("VM length overflow")?;
        take(image, at, end.checked_sub(at).context("VM size underflow")?)?;
        let count = u32_at(image, at + 4)? as usize;
        ensure!((1..=65536).contains(&count), "invalid VM stream count");
        let stream_bytes = u32_at(image, at + 8)? as usize;
        let mut p = at + 12;
        let mut streams = Vec::new();
        for _ in 0..count {
            let rva = u32_at(image, p)?;
            let n = u32_at(image, p + 4)? as usize;
            p += 8;
            take(image, p, n)?;
            streams.push((rva, p as u32, n));
            p += n;
        }
        ensure!(p - (at + 12) == stream_bytes, "VM stream size mismatch");
        let n = u32_at(image, p)? as usize;
        p += 4;
        ensure!(n <= 65536, "too many VM handlers");
        let mut handlers = HashMap::new();
        for _ in 0..n {
            let id = u32_at(image, p)?;
            let size = u32_at(image, p + 4)? as usize;
            p += 8;
            ensure!(
                handlers
                    .insert(id, take(image, p, size)?.to_vec())
                    .is_none(),
                "duplicate VM handler"
            );
            p += size;
        }
        let mut patch = [0; 12];
        for (i, offset) in patch.iter_mut().enumerate() {
            *offset = u32_at(image, p + i * 4)?;
        }
        p += 48;
        let size = patch[11] as usize;
        ensure!(
            p + size == end && size <= 0x10000,
            "invalid VM dispatcher extent"
        );
        for &offset in &patch[..9] {
            ensure!(offset as usize + 4 <= size, "VM patch outside dispatcher");
        }
        ensure!(
            (patch[9] as usize) < size && (patch[10] as usize) < size,
            "invalid dispatcher entry"
        );
        let dispatcher = take(image, p, size)?.to_vec();
        let mut decode = Decoder::with_ip(32, &dispatcher, 0, DecoderOptions::NONE);
        let mut last = None;
        while decode.can_decode() {
            last = Some(decode.decode());
        }
        let last = last.context("empty VM dispatcher")?;
        ensure!(
            last.flow_control() == iced_x86::FlowControl::UnconditionalBranch
                && last.near_branch32() < patch[10],
            "VM continuation does not return to a decoder"
        );
        let nt = u32_at(image, 0x3c)? as usize;
        let base = u32_at(image, nt + 24 + 28)?;
        Ok(Self {
            base,
            trampoline: base
                .checked_add(super::loader::Bootstrap::parse(image)?.trampoline)
                .context("VM trampoline overflow")?,
            decoder: last.near_branch32(),
            streams,
            handlers,
            patch,
            dispatcher,
        })
    }
}

pub fn stub_token_at(loader: &[u8], rva: u32, key: u32, dispatch: u32) -> Result<u32> {
    ensure!((rva as usize) < loader.len(), "IAT stub outside Loader");
    let mut image = Image::default();
    image.add(BASE, loader.to_vec())?;
    let mut state = State::new(BASE + rva, STACK);
    state.write(&image, STACK, 4, Value::constant(STOP));
    let mut token = None;
    static_x86::analyze(&mut image, state, |image, state| {
        if state.pc == BASE + dispatch {
            let encoded = state
                .read(image, state.esp()?, 4)
                .require("IAT dispatch token")?;
            let value = encoded ^ key;
            ensure!(
                token.is_none_or(|previous| previous == value),
                "IAT token depends on input state"
            );
            token = Some(value);
            return Ok(Action::Finish);
        }
        ensure!(
            state.pc.wrapping_sub(BASE) < loader.len() as u32,
            "IAT stub leaves Loader before dispatch"
        );
        Ok(Action::Decode)
    })?;
    token.context("IAT stub did not statically resolve to dispatcher")
}
