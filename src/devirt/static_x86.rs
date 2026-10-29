//! Bounded abstract interpretation of x86 basic blocks, never native execution.
//! Unknown input bits stay unknown. Conditional edges are both explored unless
//! their flags prove a direction. Joins discard information, never invent it.
use anyhow::{Context, Result, bail, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic as M, OpKind, Register as R,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

const CF: u32 = 1;
const PF: u32 = 4;
const AF: u32 = 16;
const ZF: u32 = 64;
const SF: u32 = 128;
const OF: u32 = 2048;
const ARITH: u32 = CF | PF | AF | ZF | SF | OF;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Value {
    pub bits: u32,
    pub known: u32,
    // Nonzero: exactly two candidates, `bits` and `bits ^ choice`.
    // Unlike known bits, this retains correlation between differing bits.
    choice: u32,
    // An uninterpreted input identity, plus a bit offset for narrow copies.
    tag: u32,
    shift: i16,
}
impl Value {
    pub const UNKNOWN: Self = Self {
        bits: 0,
        known: 0,
        choice: 0,
        tag: 0,
        shift: 0,
    };
    pub fn constant(bits: u32) -> Self {
        Self {
            bits,
            known: u32::MAX,
            choice: 0,
            tag: 0,
            shift: 0,
        }
    }
    pub fn input(tag: u32) -> Self {
        Self {
            tag,
            ..Self::UNKNOWN
        }
    }
    pub fn unknown_flags() -> Self {
        Self {
            bits: 2,
            known: 2,
            choice: 0,
            tag: 0,
            shift: 0,
        }
    }
    pub fn get(self) -> Option<u32> {
        (self.known == u32::MAX).then_some(self.bits)
    }
    pub fn require(self, what: &str) -> Result<u32> {
        self.get()
            .with_context(|| format!("static {what} is not constant: {self:?}"))
    }
    fn bit(self, bit: u32) -> Option<bool> {
        (self.known & bit != 0).then_some(self.bits & bit != 0)
    }
    fn mask(width: u32) -> u32 {
        if width == 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        }
    }
    fn extract(self, offset: u32, width: u32) -> Self {
        let mask = Self::mask(width);
        if self.choice != 0 {
            return Self::pair(
                (self.bits >> offset) & mask,
                ((self.bits ^ self.choice) >> offset) & mask,
            );
        }
        Self {
            bits: (self.bits >> offset) & mask,
            known: ((self.known >> offset) & mask) | !mask,
            choice: 0,
            tag: self.tag,
            shift: self.shift + offset as i16,
        }
    }
    fn insert(self, part: Self, offset: u32, width: u32) -> Self {
        let mask = Self::mask(width) << offset;
        if width == 32 {
            return part;
        }
        if (self.choice != 0 || part.choice != 0)
            && let Some(value) = self.combine(part, |a, b| (a & !mask) | ((b << offset) & mask))
        {
            return value;
        }
        let same =
            self.tag != 0 && self.tag == part.tag && self.shift + offset as i16 == part.shift;
        // Byte stores may place the beginning of an input in the middle of a
        // word. Retain its identity while other bits are known, then assemble
        // the same identity again across an unaligned load.
        let new_identity = part.tag != 0 && self.known | mask == u32::MAX;
        Self {
            bits: (self.bits & !mask) | ((part.bits << offset) & mask),
            known: (self.known & !mask) | ((part.known << offset) & mask),
            choice: 0,
            tag: if same {
                self.tag
            } else if new_identity {
                part.tag
            } else {
                0
            },
            shift: if same {
                self.shift
            } else if new_identity {
                part.shift - offset as i16
            } else {
                0
            },
        }
    }
    pub(crate) fn join(self, other: Self) -> Self {
        if self == other {
            return self;
        }
        let known = self.known & other.known & !(self.bits ^ other.bits);
        if let Some(a) = self.candidates()
            && let Some(b) = other.candidates()
        {
            let values = [a[0], a[1], b[0], b[1]];
            let lo = *values.iter().min().unwrap();
            let hi = *values.iter().max().unwrap();
            if values.iter().all(|&v| v == lo || v == hi) {
                return Self::pair(lo, hi);
            }
        }
        Self {
            bits: self.bits & known,
            known,
            choice: 0,
            tag: 0,
            shift: 0,
        }
    }
    fn same(self, other: Self) -> bool {
        self == other && (self.tag != 0 || self.get().is_some())
    }
    fn pair(a: u32, b: u32) -> Self {
        Self {
            bits: a.min(b),
            known: !(a ^ b),
            choice: a ^ b,
            tag: 0,
            shift: 0,
        }
    }
    pub(crate) fn candidates(self) -> Option<[u32; 2]> {
        if self.choice != 0 {
            Some([self.bits, self.bits ^ self.choice])
        } else if (!self.known).count_ones() <= 1 {
            Some([
                self.bits & self.known,
                (self.bits & self.known) | !self.known,
            ])
        } else {
            None
        }
    }
    fn combine(self, other: Self, f: impl Fn(u32, u32) -> u32) -> Option<Self> {
        let a = self.candidates()?;
        let b = other.candidates()?;
        let values = [f(a[0], b[0]), f(a[0], b[1]), f(a[1], b[0]), f(a[1], b[1])];
        let lo = *values.iter().min().unwrap();
        let hi = *values.iter().max().unwrap();
        (values.iter().all(|&v| v == lo || v == hi)).then(|| Self::pair(lo, hi))
    }
    pub(crate) fn assume_zero(self, zero: bool) -> Self {
        if let Some(values) = self.candidates() {
            let mut valid = values.into_iter().filter(|&v| (v == 0) == zero);
            if let Some(a) = valid.next() {
                return Self::pair(a, valid.next().unwrap_or(a));
            }
        }
        self
    }
    fn op(self, other: Self, op: M, width: u32) -> Self {
        let mask = Self::mask(width);
        let a = self.extract(0, width);
        let b = other.extract(0, width);
        if matches!(op, M::Xor | M::Sub | M::Cmp) && a.same(b) {
            return Self::constant(0);
        }
        if b.get() == Some(0) && matches!(op, M::Add | M::Sub | M::Xor | M::Or) {
            return a;
        }
        if b.get() == Some(mask) && op == M::And {
            return a;
        }
        if op == M::Imul && (a.get() == Some(0) || b.get() == Some(0)) {
            return Self::constant(0);
        }
        if let Some(value) = a.combine(b, |a, b| match op {
            M::Add => a.wrapping_add(b) & mask,
            M::Sub | M::Cmp => a.wrapping_sub(b) & mask,
            M::Imul => a.wrapping_mul(b) & mask,
            M::And | M::Test => a & b,
            M::Or => a | b,
            M::Xor => a ^ b,
            _ => unreachable!(),
        }) {
            return value;
        }
        let (bits, known) = match op {
            M::And | M::Test => (
                a.bits & b.bits,
                (a.known & b.known) | (a.known & !a.bits) | (b.known & !b.bits),
            ),
            M::Or => (
                a.bits | b.bits,
                (a.known & b.known) | (a.known & a.bits) | (b.known & b.bits),
            ),
            M::Xor => (a.bits ^ b.bits, a.known & b.known),
            _ => {
                if let (Some(a), Some(b)) = (a.get(), b.get()) {
                    let v = match op {
                        M::Add => a.wrapping_add(b),
                        M::Sub | M::Cmp => a.wrapping_sub(b),
                        M::Imul => a.wrapping_mul(b),
                        _ => unreachable!(),
                    };
                    return Self::constant(v & mask);
                }
                return Self::UNKNOWN.extract(0, width);
            }
        };
        Self {
            bits: bits & known & mask,
            known: known | !mask,
            choice: 0,
            tag: 0,
            shift: 0,
        }
    }
}

#[derive(Default)]
pub(crate) struct Image {
    regions: BTreeMap<u32, Vec<u8>>,
    zero: Vec<(u32, u32)>,
    decoded: HashMap<u32, Instruction>,
    leaders: HashSet<u32>,
}
impl Image {
    pub fn add(&mut self, address: u32, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            !bytes.is_empty() && address.checked_add(bytes.len() as u32).is_some(),
            "invalid static code region"
        );
        if let Some(previous) = self.regions.get(&address) {
            ensure!(previous == &bytes, "conflicting static code region");
            return Ok(());
        }
        self.leaders.insert(address);
        // Decode only to identify basic-block leaders; each reached instruction
        // is decoded independently too, so embedded constants are never executed.
        let mut decoder = Decoder::with_ip(32, &bytes, address as u64, DecoderOptions::NONE);
        while bytes.len() <= 0x10000 && decoder.can_decode() {
            let i = decoder.decode();
            match i.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    self.leaders.insert(i.near_branch32());
                    self.leaders.insert(i.next_ip32());
                }
                FlowControl::IndirectBranch
                | FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::Return => {
                    self.leaders.insert(i.next_ip32());
                }
                _ => {}
            }
        }
        self.regions.insert(address, bytes);
        Ok(())
    }
    pub fn zero(&mut self, start: u32, length: u32) {
        self.zero.push((start, length));
    }
    fn byte(&self, address: u32) -> Option<u8> {
        for (&base, bytes) in self.regions.range(..=address).rev() {
            if let Some(&b) = bytes.get((address - base) as usize) {
                return Some(b);
            }
        }
        self.zero
            .iter()
            .any(|&(a, n)| address.wrapping_sub(a) < n)
            .then_some(0)
    }
    fn word(&self, address: u32) -> Value {
        let mut bits = 0;
        let mut known = 0;
        for i in 0..4 {
            if let Some(byte) = self.byte(address.wrapping_add(i)) {
                bits |= (byte as u32) << (i * 8);
                known |= 255 << (i * 8);
            }
        }
        Value {
            bits,
            known,
            choice: 0,
            tag: 0,
            shift: 0,
        }
    }
    pub fn instruction(&mut self, address: u32) -> Result<Instruction> {
        if let Some(&i) = self.decoded.get(&address) {
            return Ok(i);
        }
        let bytes: Vec<_> = (0..15)
            .map_while(|i| self.byte(address.wrapping_add(i)))
            .collect();
        let i = Decoder::with_ip(32, &bytes, address as u64, DecoderOptions::NONE).decode();
        ensure!(
            !i.is_invalid(),
            "invalid static instruction at {address:#x}"
        );
        if matches!(
            i.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) {
            self.leaders.insert(i.near_branch32());
            self.leaders.insert(i.next_ip32());
        }
        self.decoded.insert(address, i);
        Ok(i)
    }
    pub fn patch(&mut self, address: u32, bytes: &[u8]) -> Result<()> {
        let (&base, region) = self
            .regions
            .range_mut(..=address)
            .next_back()
            .context("patch is outside static image")?;
        let at = (address - base) as usize;
        let destination = region
            .get_mut(at..at + bytes.len())
            .context("patch exceeds static image region")?;
        destination.copy_from_slice(bytes);
        self.decoded.clear();
        Ok(())
    }
    pub fn replace_region(&mut self, address: u32, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            !bytes.is_empty() && address.checked_add(bytes.len() as u32).is_some(),
            "invalid replacement image region"
        );
        self.regions.insert(address, bytes);
        self.decoded.clear();
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct State {
    pub pc: u32,
    pub registers: [Value; 8],
    pub flags: Value,
    pub step: u32,
    memory: Arc<HashMap<u32, Value>>,
    bytes: Arc<HashMap<u32, Value>>,
    calls: Vec<(u32, u32)>,
    pub exact_memory: bool,
}
impl State {
    pub fn new(pc: u32, esp: u32) -> Self {
        let mut registers = std::array::from_fn(|i| Value::input(1 + i as u32));
        registers[4] = Value::constant(esp);
        Self {
            pc,
            registers,
            flags: Value {
                bits: 2,
                known: 2,
                choice: 0,
                tag: 16,
                shift: 0,
            },
            step: 0,
            memory: Default::default(),
            bytes: Default::default(),
            calls: Vec::new(),
            exact_memory: false,
        }
    }
    pub fn esp(&self) -> Result<u32> {
        self.registers[4].require("stack pointer")
    }
    fn word(&self, image: &Image, address: u32) -> Value {
        self.memory
            .get(&address)
            .copied()
            .unwrap_or_else(|| image.word(address))
    }
    pub fn read(&self, image: &Image, address: u32, size: u32) -> Value {
        let offset = address & 3;
        let first = self.word(image, address & !3);
        if offset + size <= 4 && (first.get().is_some() || first.tag != 0 || first.choice != 0) {
            return first.extract(offset * 8, size * 8);
        }
        let mut result = Value::constant(0);
        for i in 0..size {
            let byte = self.byte(image, address.wrapping_add(i));
            result = result.insert(byte, i * 8, 8);
        }
        result
    }
    pub fn write(&mut self, image: &Image, address: u32, size: u32, value: Value) {
        for i in 0..size {
            Arc::make_mut(&mut self.bytes).insert(address.wrapping_add(i), value.extract(i * 8, 8));
        }
        if size == 4 && address & 3 == 0 {
            Arc::make_mut(&mut self.memory).insert(address, value);
            return;
        }
        for i in 0..size {
            let at = address.wrapping_add(i);
            let base = at & !3;
            let word = self
                .word(image, base)
                .insert(value.extract(i * 8, 8), (at & 3) * 8, 8);
            Arc::make_mut(&mut self.memory).insert(base, word);
        }
    }
    pub(crate) fn forget(&mut self, address: u32, size: u32) {
        for offset in 0..size {
            Arc::make_mut(&mut self.bytes).remove(&address.wrapping_add(offset));
            Arc::make_mut(&mut self.memory).remove(&(address.wrapping_add(offset) & !3));
        }
    }
    pub(crate) fn live_memory(&self, low: u32) -> Vec<(u32, Value)> {
        let mut words = self
            .memory
            .iter()
            .filter(|&(&at, _)| at >= low)
            .map(|(&at, &value)| (at, value))
            .collect::<Vec<_>>();
        words.sort_unstable_by_key(|&(at, _)| at);
        words
    }
    fn byte(&self, image: &Image, address: u32) -> Value {
        self.bytes
            .get(&address)
            .copied()
            .unwrap_or_else(|| self.word(image, address & !3).extract((address & 3) * 8, 8))
    }
    pub fn push(&mut self, image: &Image, value: Value) -> Result<()> {
        self.push_sized(image, value, 4)
    }
    fn push_sized(&mut self, image: &Image, value: Value, size: u32) -> Result<()> {
        let esp = self.esp()?.wrapping_sub(size);
        self.registers[4] = Value::constant(esp);
        self.write(image, esp, size, value);
        Ok(())
    }
    pub fn pop(&mut self, image: &Image) -> Result<Value> {
        self.pop_sized(image, 4)
    }
    fn pop_sized(&mut self, image: &Image, size: u32) -> Result<Value> {
        let esp = self.esp()?;
        let value = self.read(image, esp, size);
        self.registers[4] = Value::constant(esp.wrapping_add(size));
        Ok(value)
    }
    pub fn return_from(&mut self, image: &Image, consumed: u32) -> Result<()> {
        self.pc = self.pop(image)?.require("return target")?;
        self.registers[4] = Value::constant(self.esp()?.wrapping_add(consumed));
        Ok(())
    }
    pub(crate) fn join(&mut self, other: &Self, image: &Image) -> bool {
        let mut changed = false;
        for (a, b) in self.registers.iter_mut().zip(other.registers) {
            let n = a.join(b);
            changed |= *a != n;
            *a = n;
        }
        let flags = self.flags.join(other.flags);
        changed |= flags != self.flags;
        self.flags = flags;
        let keys: HashSet<_> = self
            .memory
            .keys()
            .chain(other.memory.keys())
            .copied()
            .collect();
        for at in keys {
            let a = self.word(image, at);
            let n = a.join(other.word(image, at));
            if a != n {
                Arc::make_mut(&mut self.memory).insert(at, n);
                changed = true;
            }
        }
        let keys: HashSet<_> = self
            .bytes
            .keys()
            .chain(other.bytes.keys())
            .copied()
            .collect();
        for at in keys {
            let a = self.byte(image, at);
            let n = a.join(other.byte(image, at));
            if a != n {
                Arc::make_mut(&mut self.bytes).insert(at, n);
                changed = true;
            }
        }
        changed
    }
    fn flag(&mut self, bit: u32, value: Option<bool>) {
        self.flags.choice = 0;
        self.flags.tag = 0;
        self.flags.known &= !bit;
        self.flags.bits &= !bit;
        if let Some(value) = value {
            self.flags.known |= bit;
            if value {
                self.flags.bits |= bit;
            }
        }
    }
    fn zsp(&mut self, result: Value, width: u32) {
        let mask = Value::mask(width);
        let r = result.extract(0, width);
        self.flag(
            ZF,
            if r.bits & r.known & mask != 0
                || r.candidates()
                    .is_some_and(|values| values.iter().all(|&v| v != 0))
            {
                Some(false)
            } else {
                r.get().map(|v| v == 0)
            },
        );
        self.flag(SF, r.bit(1 << (width - 1)));
        self.flag(
            PF,
            (r.known & 255 == 255).then_some((r.bits & 255).count_ones().is_multiple_of(2)),
        );
    }
    fn alu_flags(&mut self, op: M, a: Value, b: Value, result: Value, width: u32) {
        self.zsp(result, width);
        if matches!(op, M::And | M::Or | M::Xor | M::Test) {
            self.flag(CF, Some(false));
            self.flag(OF, Some(false));
            self.flag(AF, None);
            return;
        }
        if matches!(op, M::Sub | M::Cmp) && a.same(b) {
            self.flag(CF, Some(false));
            self.flag(OF, Some(false));
            self.flag(AF, Some(false));
            return;
        }
        let values = a.get().zip(b.get()).zip(result.get());
        let cf = values.map(|((a, b), _)| {
            if op == M::Add {
                a as u64 + b as u64 > Value::mask(width) as u64
            } else {
                a < b
            }
        });
        let of = values.map(|((a, b), r)| {
            let sign = 1 << (width - 1);
            if op == M::Add {
                (!(a ^ b) & (a ^ r) & sign) != 0
            } else {
                ((a ^ b) & (a ^ r) & sign) != 0
            }
        });
        let af = values.map(|((a, b), r)| (a ^ b ^ r) & 16 != 0);
        self.flag(CF, cf);
        self.flag(OF, of);
        self.flag(AF, af);
    }
}

pub(crate) fn register(r: R) -> Result<(usize, u32, u32)> {
    let (index, offset, width) = match r {
        R::EAX | R::AX | R::AL | R::AH => (
            0,
            if r == R::AH { 8 } else { 0 },
            if r == R::EAX {
                32
            } else if r == R::AX {
                16
            } else {
                8
            },
        ),
        R::ECX | R::CX | R::CL | R::CH => (
            1,
            if r == R::CH { 8 } else { 0 },
            if r == R::ECX {
                32
            } else if r == R::CX {
                16
            } else {
                8
            },
        ),
        R::EDX | R::DX | R::DL | R::DH => (
            2,
            if r == R::DH { 8 } else { 0 },
            if r == R::EDX {
                32
            } else if r == R::DX {
                16
            } else {
                8
            },
        ),
        R::EBX | R::BX | R::BL | R::BH => (
            3,
            if r == R::BH { 8 } else { 0 },
            if r == R::EBX {
                32
            } else if r == R::BX {
                16
            } else {
                8
            },
        ),
        R::ESP | R::SP => (4, 0, if r == R::ESP { 32 } else { 16 }),
        R::EBP | R::BP => (5, 0, if r == R::EBP { 32 } else { 16 }),
        R::ESI | R::SI => (6, 0, if r == R::ESI { 32 } else { 16 }),
        R::EDI | R::DI => (7, 0, if r == R::EDI { 32 } else { 16 }),
        _ => bail!("unsupported static register {r:?}"),
    };
    Ok((index, offset, width))
}
pub(crate) fn reg(state: &State, r: R) -> Result<Value> {
    if r == R::None {
        return Ok(Value::constant(0));
    }
    let (i, o, w) = register(r)?;
    Ok(state.registers[i].extract(o, w))
}
pub(crate) fn set_reg(state: &mut State, r: R, v: Value) -> Result<()> {
    let (i, o, w) = register(r)?;
    state.registers[i] = if w == 32 {
        v
    } else {
        state.registers[i].insert(v, o, w)
    };
    Ok(())
}
pub(crate) fn address(state: &State, i: &Instruction) -> Result<Value> {
    ensure!(
        matches!(i.memory_segment(), R::DS | R::SS | R::ES | R::None),
        "unsupported static segment"
    );
    let base = reg(state, i.memory_base())?;
    let index = reg(state, i.memory_index())?;
    let scaled = index.op(Value::constant(i.memory_index_scale()), M::Imul, 32);
    Ok(base
        .op(scaled, M::Add, 32)
        .op(Value::constant(i.memory_displacement32()), M::Add, 32))
}
pub(crate) fn width(i: &Instruction, n: u32) -> Result<u32> {
    if i.op_kind(n) == OpKind::Register {
        return Ok(register(i.op_register(n))?.2);
    }
    if i.op_kind(n) == OpKind::Memory {
        let w = i.memory_size().size() as u32 * 8;
        ensure!(
            matches!(w, 8 | 16 | 32),
            "unsupported static memory width {w}"
        );
        return Ok(w);
    }
    Ok(32)
}
pub(crate) fn operand(state: &State, image: &Image, i: &Instruction, n: u32) -> Result<Value> {
    Ok(match i.op_kind(n) {
        OpKind::Register => reg(state, i.op_register(n))?,
        OpKind::Memory => address(state, i)?.get().map_or(Value::UNKNOWN, |at| {
            state.read(image, at, (i.memory_size().size()) as u32)
        }),
        OpKind::NearBranch32 => Value::constant(i.near_branch32()),
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Value::constant(i.immediate(n) as u32),
        k => bail!("unsupported static operand {k:?}"),
    })
}
fn assign(state: &mut State, image: &Image, i: &Instruction, n: u32, v: Value) -> Result<()> {
    match i.op_kind(n) {
        OpKind::Register => set_reg(state, i.op_register(n), v),
        OpKind::Memory => {
            let at = address(state, i)?.require("write address")?;
            state.write(image, at, i.memory_size().size() as u32, v);
            Ok(())
        }
        _ => bail!("unsupported static destination"),
    }
}
fn not(a: Option<bool>) -> Option<bool> {
    a.map(|a| !a)
}
fn and(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    if a == Some(false) || b == Some(false) {
        Some(false)
    } else {
        a.zip(b).map(|(a, b)| a && b)
    }
}
fn or(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    if a == Some(true) || b == Some(true) {
        Some(true)
    } else {
        a.zip(b).map(|(a, b)| a || b)
    }
}
fn condition(state: &State, m: M) -> Result<Option<bool>> {
    let f = state.flags;
    let (c, p, z, s, o) = (f.bit(CF), f.bit(PF), f.bit(ZF), f.bit(SF), f.bit(OF));
    let eq = s.zip(o).map(|(a, b)| a == b);
    Ok(match m {
        M::Je | M::Sete | M::Cmove => z,
        M::Jne | M::Setne | M::Cmovne => not(z),
        M::Jb | M::Setb | M::Cmovb => c,
        M::Jae | M::Setae | M::Cmovae => not(c),
        M::Jbe | M::Setbe | M::Cmovbe => or(c, z),
        M::Ja | M::Seta | M::Cmova => and(not(c), not(z)),
        M::Js | M::Sets | M::Cmovs => s,
        M::Jns | M::Setns | M::Cmovns => not(s),
        M::Jo | M::Seto | M::Cmovo => o,
        M::Jno | M::Setno | M::Cmovno => not(o),
        M::Jp | M::Setp | M::Cmovp => p,
        M::Jnp | M::Setnp | M::Cmovnp => not(p),
        M::Jl | M::Setl | M::Cmovl => not(eq),
        M::Jge | M::Setge | M::Cmovge => eq,
        M::Jle | M::Setle | M::Cmovle => or(z, not(eq)),
        M::Jg | M::Setg | M::Cmovg => and(not(z), eq),
        _ => bail!("unsupported static condition {m:?}"),
    })
}

fn shift(state: &mut State, op: M, a: Value, b: Value, w: u32) -> Value {
    let Some(count) = b.get().map(|b| b & 31) else {
        state.flags.choice = 0;
        state.flags.known &= !ARITH;
        state.flags.tag = 0;
        return Value::UNKNOWN.extract(0, w);
    };
    if count == 0 {
        return a;
    }
    let mask = Value::mask(w);
    let c = if matches!(op, M::Rol | M::Ror) {
        count % w
    } else {
        count
    };
    if c == 0 {
        return a;
    }
    let transform = |v: u32| match op {
        M::Shl => v.wrapping_shl(c) & mask,
        M::Shr => v.wrapping_shr(c),
        M::Sar => ((v.wrapping_shl(32 - w) as i32) >> (32 - w)).wrapping_shr(c) as u32 & mask,
        M::Rol => ((v << c) | (v >> (w - c))) & mask,
        M::Ror => ((v >> c) | (v << (w - c))) & mask,
        _ => unreachable!(),
    };
    let value = a
        .candidates()
        .map(|[a, b]| Value::pair(transform(a), transform(b)))
        .unwrap_or_else(|| {
            let (bits, known) = match op {
                M::Shl => (
                    a.bits.wrapping_shl(c),
                    a.known.wrapping_shl(c) | ((1u32 << c) - 1),
                ),
                M::Shr => (a.bits >> c, (a.known >> c) | (!0u32 << (32 - c))),
                M::Sar => {
                    let bits = (((a.bits << (32 - w)) as i32 >> (32 - w)) >> c) as u32;
                    let sign = 1u32 << (w - 1);
                    let fill = if a.known & sign != 0 {
                        mask ^ (mask >> c.min(w))
                    } else {
                        0
                    };
                    (bits, (a.known >> c) | fill)
                }
                M::Rol => (
                    (a.bits << c) | (a.bits >> (w - c)),
                    (a.known << c) | (a.known >> (w - c)),
                ),
                M::Ror => (
                    (a.bits >> c) | (a.bits << (w - c)),
                    (a.known >> c) | (a.known << (w - c)),
                ),
                _ => unreachable!(),
            };
            Value {
                bits: bits & known & mask,
                known: known | !mask,
                choice: 0,
                tag: 0,
                shift: 0,
            }
        });
    if matches!(op, M::Rol | M::Ror) {
        state.flag(CF, value.bit(if op == M::Rol { 1 } else { 1 << (w - 1) }));
        let of = if count == 1 {
            let x = value.bit(1 << (w - 1));
            let y = value.bit(if op == M::Rol { 1 } else { 1 << (w - 2) });
            x.zip(y).map(|(x, y)| x ^ y)
        } else {
            None
        };
        state.flag(OF, of);
    } else {
        state.zsp(value, w);
        state.flag(AF, None);
        let cf = if c <= w {
            a.bit(if op == M::Shl {
                1 << (w - c)
            } else {
                1 << (c - 1)
            })
        } else {
            None
        };
        state.flag(CF, cf);
        state.flag(
            OF,
            if count == 1 {
                match op {
                    M::Shl => value.bit(1 << (w - 1)).zip(cf).map(|(a, b)| a ^ b),
                    M::Shr => a.bit(1 << (w - 1)),
                    M::Sar => Some(false),
                    _ => None,
                }
            } else {
                None
            },
        );
    }
    value
}

pub(crate) fn execute(state: &mut State, image: &Image, i: &Instruction) -> Result<Option<State>> {
    let m = i.mnemonic();
    state.pc = i.next_ip32();
    match m {
        M::Nop => {}
        M::Seto
        | M::Setno
        | M::Setb
        | M::Setae
        | M::Sete
        | M::Setne
        | M::Setbe
        | M::Seta
        | M::Sets
        | M::Setns
        | M::Setp
        | M::Setnp
        | M::Setl
        | M::Setge
        | M::Setle
        | M::Setg => {
            let value =
                condition(state, m)?.map_or(Value::pair(0, 1), |v| Value::constant(u32::from(v)));
            assign(state, image, i, 0, value)?;
        }
        M::Cmova
        | M::Cmovae
        | M::Cmovb
        | M::Cmovbe
        | M::Cmove
        | M::Cmovne
        | M::Cmovg
        | M::Cmovge
        | M::Cmovl
        | M::Cmovle
        | M::Cmovs
        | M::Cmovns
        | M::Cmovo
        | M::Cmovno
        | M::Cmovp
        | M::Cmovnp => {
            let source = operand(state, image, i, 1)?;
            let value = match condition(state, m)? {
                Some(true) => source,
                Some(false) => operand(state, image, i, 0)?,
                None => operand(state, image, i, 0)?.join(source),
            };
            assign(state, image, i, 0, value)?;
        }
        M::Mov | M::Movzx | M::Movsx => {
            let mut v = operand(state, image, i, 1)?;
            if m == M::Movsx {
                let w = width(i, 1)?;
                v = v
                    .get()
                    .map(|v| ((v << (32 - w)) as i32 >> (32 - w)) as u32)
                    .map_or(Value::UNKNOWN, Value::constant);
            }
            assign(state, image, i, 0, v)?;
        }
        M::Lea => {
            let v = address(state, i)?;
            assign(state, image, i, 0, v)?;
        }
        M::Xchg => {
            let a = operand(state, image, i, 0)?;
            let b = operand(state, image, i, 1)?;
            // Both effective addresses are evaluated before either register
            // changes (e.g. XCHG EAX,[EAX]).
            let at = if i.op_kind(0) == OpKind::Memory || i.op_kind(1) == OpKind::Memory {
                Some(address(state, i)?.require("exchange address")?)
            } else {
                None
            };
            for (n, value) in [(0, b), (1, a)] {
                if i.op_kind(n) == OpKind::Memory {
                    state.write(image, at.unwrap(), i.memory_size().size() as u32, value);
                } else {
                    assign(state, image, i, n, value)?;
                }
            }
        }
        M::Push => {
            let size = (-i.stack_pointer_increment()) as u32;
            ensure!(matches!(size, 2 | 4), "unsupported static PUSH width");
            let v = operand(state, image, i, 0)?;
            state.push_sized(image, v, size)?;
        }
        M::Pop => {
            let size = i.stack_pointer_increment() as u32;
            ensure!(matches!(size, 2 | 4), "unsupported static POP width");
            let v = state.pop_sized(image, size)?;
            assign(state, image, i, 0, v)?;
        }
        M::Pushad => {
            let regs = state.registers;
            for v in regs {
                state.push(image, v)?;
            }
        }
        M::Popad => {
            for n in (0..8).rev() {
                let v = state.pop(image)?;
                if n != 4 {
                    state.registers[n] = v;
                }
            }
        }
        M::Pushfd => state.push(image, state.flags)?,
        M::Popfd => state.flags = state.pop(image)?,
        M::Pushf => state.push_sized(image, state.flags, 2)?,
        M::Popf => {
            let flags = state.pop_sized(image, 2)?;
            state.flags = state.flags.insert(flags, 0, 16);
        }
        M::Add | M::Sub | M::Xor | M::And | M::Or | M::Cmp | M::Test => {
            let w = width(i, 0)?;
            let a = operand(state, image, i, 0)?.extract(0, w);
            let b = operand(state, image, i, 1)?.extract(0, w);
            let same = i.op_kind(0) == OpKind::Register
                && i.op_kind(1) == OpKind::Register
                && i.op_register(0) == i.op_register(1);
            let v = if same && matches!(m, M::Sub | M::Cmp | M::Xor) {
                Value::constant(0)
            } else {
                a.op(b, m, w)
            };
            state.alu_flags(m, a, b, v, w);
            if same && matches!(m, M::Sub | M::Cmp) {
                state.flag(CF, Some(false));
                state.flag(OF, Some(false));
                state.flag(AF, Some(false));
            }
            if !matches!(m, M::Cmp | M::Test) {
                assign(state, image, i, 0, v)?;
            }
        }
        M::Inc | M::Dec | M::Neg | M::Not | M::Bswap => {
            let w = width(i, 0)?;
            let a = operand(state, image, i, 0)?;
            let v = match m {
                M::Inc => a.op(Value::constant(1), M::Add, w),
                M::Dec => a.op(Value::constant(1), M::Sub, w),
                M::Neg => Value::constant(0).op(a, M::Sub, w),
                M::Not => a
                    .candidates()
                    .map_or(
                        Value {
                            bits: !a.bits & a.known,
                            known: a.known,
                            choice: 0,
                            tag: 0,
                            shift: 0,
                        },
                        |[a, b]| Value::pair(!a, !b),
                    )
                    .extract(0, w),
                M::Bswap => a.candidates().map_or(
                    Value {
                        bits: a.bits.swap_bytes(),
                        known: a.known.swap_bytes(),
                        choice: 0,
                        tag: 0,
                        shift: 0,
                    },
                    |[a, b]| Value::pair(a.swap_bytes(), b.swap_bytes()),
                ),
                _ => unreachable!(),
            };
            if matches!(m, M::Inc | M::Dec) {
                let cf = state.flags.bit(CF);
                state.alu_flags(
                    if m == M::Inc { M::Add } else { M::Sub },
                    a,
                    Value::constant(1),
                    v,
                    w,
                );
                state.flag(CF, cf);
            } else if m == M::Neg {
                state.alu_flags(M::Sub, Value::constant(0), a, v, w);
            }
            assign(state, image, i, 0, v)?;
        }
        M::Shl | M::Shr | M::Sar | M::Rol | M::Ror => {
            let a = operand(state, image, i, 0)?;
            let b = operand(state, image, i, 1)?;
            let v = shift(state, m, a, b, width(i, 0)?);
            assign(state, image, i, 0, v)?;
        }
        M::Mul => {
            ensure!(width(i, 0)? == 32, "unsupported static MUL width");
            let product = state.registers[0]
                .get()
                .zip(operand(state, image, i, 0)?.get())
                .map(|(a, b)| a as u64 * b as u64);
            state.registers[0] = product.map_or(Value::UNKNOWN, |p| Value::constant(p as u32));
            state.registers[2] =
                product.map_or(Value::UNKNOWN, |p| Value::constant((p >> 32) as u32));
            state.flags.known &= !ARITH;
            state.flags.tag = 0;
            state.flag(CF, product.map(|p| p >> 32 != 0));
            state.flag(OF, product.map(|p| p >> 32 != 0));
        }
        M::Imul => {
            ensure!(
                i.op_count() == 2 || i.op_count() == 3,
                "unsupported static multiply"
            );
            let w = width(i, 0)?;
            let a = operand(state, image, i, if i.op_count() == 3 { 1 } else { 0 })?;
            let b = operand(state, image, i, if i.op_count() == 3 { 2 } else { 1 })?;
            let v = a.op(b, M::Imul, w);
            assign(state, image, i, 0, v)?;
            state.flags.known &= !ARITH;
            state.flags.tag = 0;
            let overflow = a.get().zip(b.get()).map(|(a, b)| {
                let a = ((a << (32 - w)) as i32 >> (32 - w)) as i64;
                let b = ((b << (32 - w)) as i32 >> (32 - w)) as i64;
                let p = a * b;
                p < -(1i64 << (w - 1)) || p >= (1i64 << (w - 1))
            });
            state.flag(CF, overflow);
            state.flag(OF, overflow);
        }
        M::Jmp => state.pc = operand(state, image, i, 0)?.require("jump target")?,
        M::Call => {
            let target = operand(state, image, i, 0)?.require("call target")?;
            state.push(image, Value::constant(i.next_ip32()))?;
            state.calls.retain(|&(at, _)| at > state.registers[4].bits);
            state.calls.push((state.esp()?, i.next_ip32()));
            state.pc = target;
        }
        M::Ret => {
            let consumed = if i.op_count() > 0 {
                i.immediate16() as u32
            } else {
                0
            };
            ensure!(
                i.stack_pointer_increment() == 4 + consumed as i32,
                "unsupported static return width"
            );
            state.return_from(image, consumed)?;
        }
        M::Clc => state.flag(CF, Some(false)),
        M::Stc => state.flag(CF, Some(true)),
        M::Cmc => state.flag(CF, not(state.flags.bit(CF))),
        M::Je
        | M::Jne
        | M::Jb
        | M::Jae
        | M::Jbe
        | M::Ja
        | M::Js
        | M::Jns
        | M::Jo
        | M::Jno
        | M::Jp
        | M::Jnp
        | M::Jl
        | M::Jge
        | M::Jle
        | M::Jg => match condition(state, m)? {
            Some(true) => state.pc = i.near_branch32(),
            Some(false) => {}
            None => {
                let mut branch = state.clone();
                branch.pc = i.near_branch32();
                return Ok(Some(branch));
            }
        },
        _ => bail!("unsupported static instruction {m:?} at {:#x}", i.ip()),
    }
    Ok(None)
}

pub(crate) enum Action {
    Decode,
    Finish,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Key {
    pc: u32,
    esp: u32,
    step: u32,
    calls: Vec<(u32, u32)>,
    registers: [Value; 8],
    flags: Value,
    memory: Vec<(u32, Value)>,
    bytes: Vec<(u32, Value)>,
}
fn enqueue(
    states: &mut HashMap<Key, State>,
    queue: &mut VecDeque<Key>,
    image: &Image,
    mut state: State,
    retained_words: &mut usize,
) -> Result<Key> {
    ensure!(state.memory.len() <= 32768, "static memory-state limit");
    let esp = state.esp()?;
    state.calls.retain(|&(at, _)| at >= esp);
    let mut memory = if state.exact_memory {
        state
            .memory
            .iter()
            .map(|(&at, &v)| (at, v))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    memory.sort_unstable_by_key(|&(at, _)| at);
    let mut bytes = if state.exact_memory {
        state
            .bytes
            .iter()
            .map(|(&at, &v)| (at, v))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    bytes.sort_unstable_by_key(|&(at, _)| at);
    let key = Key {
        pc: state.pc,
        esp,
        step: state.step,
        calls: state.calls.clone(),
        registers: state.registers,
        flags: state.flags,
        memory,
        bytes,
    };
    if let Some(previous) = states.get_mut(&key) {
        let before = previous.memory.len();
        if previous.join(&state, image) {
            queue.push_back(key.clone());
        }
        *retained_words += previous.memory.len() - before;
    } else {
        *retained_words += state.memory.len();
        states.insert(key.clone(), state);
        queue.push_back(key.clone());
    }
    ensure!(
        *retained_words <= 16_777_216,
        "static control-flow memory limit"
    );
    Ok(key)
}
pub(crate) fn analyze(
    image: &mut Image,
    initial: State,
    mut hook: impl FnMut(&mut Image, &mut State) -> Result<Action>,
) -> Result<()> {
    let mut states = HashMap::new();
    let mut queue = VecDeque::new();
    let mut instructions = 0;
    let mut blocks = 0;
    let mut retained_words = 0;
    let mut edges: HashMap<Key, HashSet<Key>> = HashMap::new();
    enqueue(&mut states, &mut queue, image, initial, &mut retained_words)?;
    while let Some(key) = queue.pop_front() {
        let mut state = states[&key].clone();
        blocks += 1;
        ensure!(
            blocks <= 200_000 && states.len() <= 100_000,
            "static control-flow graph exceeds bounds"
        );
        loop {
            let pc = state.pc;
            match hook(image, &mut state)
                .with_context(|| format!("static boundary at {pc:#x}, VM step {}", state.step))?
            {
                Action::Finish => break,
                Action::Decode => {}
            }
            let i = image.instruction(pc)?;
            instructions += 1;
            ensure!(
                instructions <= 2_000_000,
                "static instruction bound exceeded"
            );
            if let Some(branch) = execute(&mut state, image, &i).with_context(|| {
                format!("static {pc:#x} {:?}, VM step {}", i.mnemonic(), state.step)
            })? {
                let next = enqueue(&mut states, &mut queue, image, branch, &mut retained_words)?;
                edges.entry(key.clone()).or_default().insert(next);
            }
            if i.flow_control() != FlowControl::Next || image.leaders.contains(&state.pc) {
                let next = enqueue(&mut states, &mut queue, image, state, &mut retained_words)?;
                edges.entry(key.clone()).or_default().insert(next);
                break;
            }
        }
    }
    // A fixed point alone does not establish termination. Reject a reachable
    // cycle rather than silently dropping its path when a state stops changing.
    let mut incoming: HashMap<Key, usize> = states.keys().map(|key| (key.clone(), 0)).collect();
    for successors in edges.values() {
        for successor in successors {
            *incoming.get_mut(successor).unwrap() += 1;
        }
    }
    let mut ready: VecDeque<_> = incoming
        .iter()
        .filter_map(|(key, &n)| (n == 0).then_some(key.clone()))
        .collect();
    let mut visited = 0;
    while let Some(key) = ready.pop_front() {
        visited += 1;
        if let Some(next) = edges.get(&key) {
            for successor in next {
                let n = incoming.get_mut(successor).unwrap();
                *n -= 1;
                if *n == 0 {
                    ready.push_back(successor.clone());
                }
            }
        }
    }
    ensure!(
        visited == states.len(),
        "static path has an internal cycle without a termination proof"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../test/static_x86.rs"]
mod tests;
