//! Symbolic handler execution. Internal VM memory becomes expressions; host
//! memory remains an explicit effect. This pass never invokes native callbacks.
use super::{
    cpu::{self as x64, Image, State, Value},
    ir::{Expr, Expressions, Id},
};
use anyhow::{Context, Result, bail};
use iced_x86::{Instruction, Mnemonic as M, OpKind, Register as R};
use rustc_hash::FxHashMap as HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Store {
    pub address: Id,
    pub value: Id,
    pub width: u64,
    pub segment: R,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Predicate {
    pub flags: Id,
    pub op: M,
    pub taken: bool,
    pub epoch: u64,
}

#[derive(Clone)]
pub(crate) struct StateExpressions {
    pub cpu: State,
    pub registers: [Id; 16],
    pub flags: Id,
    pub bytes: HashMap<u64, Id>,
    pub words: HashMap<u64, Id>,
    pub stores: Vec<Store>,
    pub stack_start: u64,
    // Missing bytes below this high-water mark were deliberately forgotten.
    // A reached read must prove they have been written again before use.
    pub retired_stack: u64,
    pub stack_end: u64,
    pub internal: Vec<(u64, u64)>,
    pub conditions: Vec<Predicate>,
    pub epoch: u64,
    pub guest_sp: Option<u64>,
    pub guest_memory: HashMap<(Id, u64), (Id, Value)>,
    pub code_ranges: Vec<(u64, u64, u64)>,
    pub guest_values: HashMap<(u64, u64), Value>,
    pub image_signature: u16,
    pub initializer_words: HashMap<u64, Id>,
    pub image_base: u64,
    pub fixed_header: Arc<HashMap<u64, u8>>,
}

impl StateExpressions {
    fn refine_zero(&mut self, expressions: &Expressions, image: &Image, flags: Id, zero: bool) {
        let Some(value) = expressions.zero_test(flags) else {
            return;
        };
        for (id, numeric) in self.registers.iter().zip(&mut self.cpu.registers) {
            if *id == value {
                *numeric = numeric.assume_zero(zero);
            }
        }
        for (&at, &id) in &self.words {
            if id == value {
                let numeric = self.cpu.read(image, at, 8).assume_zero(zero);
                self.cpu.write(image, at, 8, numeric);
            }
        }
    }
    pub fn new(
        cpu: State,
        expressions: &mut Expressions,
        stack_start: u64,
        stack_end: u64,
    ) -> Self {
        let registers = std::array::from_fn(|r| expressions.input(r as u64));
        let flags = expressions.input(16);
        Self {
            cpu,
            registers,
            flags,
            bytes: HashMap::default(),
            words: HashMap::default(),
            stores: Vec::new(),
            stack_start,
            retired_stack: stack_start,
            stack_end,
            internal: Vec::new(),
            conditions: Vec::new(),
            epoch: 0,
            guest_sp: None,
            guest_memory: HashMap::default(),
            code_ranges: Vec::new(),
            guest_values: HashMap::default(),
            image_signature: 0,
            initializer_words: HashMap::default(),
            image_base: 0,
            fixed_header: Arc::default(),
        }
    }

    /// Exclude popped scratch values from CFG identity. Keep the active frame,
    /// including when a handler temporarily moves ESP above its frame pointer.
    /// Checked reads prevent this abstraction from guessing discarded values.
    pub fn retire_stack(&mut self, expressions: &mut Expressions) -> Result<()> {
        if expressions.guest_pointer(self.registers[4]) {
            return Ok(());
        }
        let mut end = (self.cpu.esp()? & !7).clamp(self.stack_start, self.stack_end);
        if let Some(frame) = self.cpu.registers[5]
            .get()
            .filter(|p| (self.stack_start..self.stack_end).contains(p))
        {
            end = end.min(frame & !7);
        }
        self.retired_stack = self.retired_stack.max(end);
        // An unaligned spill can straddle the retired range. Its bytes above
        // ESP remain live even though the cached word starts below ESP.
        for offset in 1..8 {
            let start = end.wrapping_sub(offset);
            if start >= self.stack_start
                && let Some(&word) = self.words.get(&start)
            {
                for byte in offset..8 {
                    self.bytes
                        .insert(start + byte, expressions.extract(word, byte * 8, 8));
                }
            }
        }
        self.bytes
            .retain(|&at, _| at < self.stack_start || at >= end);
        self.words
            .retain(|&at, _| at < self.stack_start || at >= end);
        self.cpu.forget_range(self.stack_start, end);
        Ok(())
    }
    pub fn check_private_read(&self, address: u64, size: u64) -> Result<()> {
        for offset in 0..size {
            let at = address.wrapping_add(offset);
            anyhow::ensure!(
                at < self.stack_start || at >= self.retired_stack || self.has_byte(at),
                "read of retired private stack byte {at:#x}"
            );
        }
        Ok(())
    }

    fn has_byte(&self, at: u64) -> bool {
        self.bytes.contains_key(&at)
            || (0..8).any(|offset| self.words.contains_key(&at.wrapping_sub(offset)))
    }

    fn stored_byte(&self, expressions: &mut Expressions, at: u64) -> Option<Id> {
        if let Some(&byte) = self.bytes.get(&at) {
            return Some(byte);
        }
        for offset in 0..8 {
            if let Some(&word) = self.words.get(&at.wrapping_sub(offset)) {
                return Some(expressions.extract(word, offset * 8, 8));
            }
        }
        None
    }

    pub fn reg(&self, expressions: &mut Expressions, register: R) -> Result<Id> {
        if register == R::None {
            return Ok(expressions.constant(0));
        }
        let (index, offset, width) = x64::register(register)?;
        Ok(expressions.extract(self.registers[index], offset, width))
    }

    fn set_reg(&mut self, expressions: &mut Expressions, register: R, value: Id) -> Result<()> {
        let (index, offset, width) = x64::register(register)?;
        self.registers[index] = if width == 32 {
            expressions.extract(value, 0, 32)
        } else {
            expressions.insert(self.registers[index], value, offset, width)
        };
        Ok(())
    }

    pub fn address(&self, expressions: &mut Expressions, i: &Instruction) -> Result<Id> {
        if i.is_ip_rel_memory_operand() {
            return Ok(expressions.constant(i.ip_rel_memory_address()));
        }
        let base = self.reg(expressions, i.memory_base())?;
        let index = self.reg(expressions, i.memory_index())?;
        let scale = expressions.constant(i.memory_index_scale() as u64);
        let index = expressions.binary(M::Imul, index, scale, 64);
        let base = expressions.binary(M::Add, base, index, 64);
        let displacement = expressions.constant(i.memory_displacement64());
        Ok(expressions.binary(M::Add, base, displacement, 64))
    }

    fn numeric_address(&self, i: &Instruction) -> Result<Option<u64>> {
        if matches!(i.memory_segment(), R::FS | R::GS) {
            return Ok(None);
        }
        Ok(x64::address(&self.cpu, i)?.get())
    }

    pub fn read(
        &self,
        expressions: &mut Expressions,
        image: &Image,
        address: u64,
        size: u64,
        pointer: Id,
    ) -> Result<Id> {
        if let Some(value) = self.header_value(Some(address), size) {
            return Ok(expressions.constant(value));
        }
        if expressions.guest_pointer(pointer) {
            return Ok(self.guest_read(expressions, pointer, size, R::DS).0);
        }
        if let Some(&word) = self.words.get(&address) {
            if let Some(value) = self.cpu.read(image, address, size).get()
                && !expressions.depends_stack(word)
                && !expressions.relocatable(word)
            {
                return Ok(expressions.constant(value));
            }
            return Ok(expressions.extract(word, 0, size * 8));
        }
        self.check_private_read(address, size)?;
        if let Some(&first) = self.bytes.get(&address)
            && let Expr::Extract(source, 0, 8) = *expressions.node(first)
            && (0..size).all(|offset| {
                self.bytes
                    .get(&address.wrapping_add(offset))
                    .is_some_and(|&byte| {
                        matches!(expressions.node(byte), Expr::Extract(input, at, 8)
                        if *input == source && *at == offset * 8)
                    })
            })
        {
            return Ok(expressions.extract(source, 0, size * 8));
        }
        let mut result = expressions.constant(0);
        for offset in 0..size {
            let at = address.wrapping_add(offset);
            let byte = if let Some(value) = self.stored_byte(expressions, at) {
                value
            } else if let Some(value) = self.cpu.read(image, at, 1).get() {
                expressions.constant(value)
            } else {
                expressions.input(0x80000000 | at)
            };
            result = expressions.insert(result, byte, offset * 8, 8);
        }
        Ok(result)
    }
    pub fn guest_read(
        &self,
        expressions: &mut Expressions,
        address: Id,
        size: u64,
        segment: R,
    ) -> (Id, Value) {
        if let Some(&value) = self.guest_memory.get(&(address, size)) {
            return value;
        }
        if size == 2 && matches!(expressions.node(address), Expr::ImageBase) {
            let value = u64::from(self.image_signature);
            return (expressions.constant(value), Value::constant(value));
        }
        (
            expressions.intern(Expr::Load(address, size * 8, segment, self.epoch)),
            Value::UNKNOWN,
        )
    }

    fn header_value(&self, address: Option<u64>, size: u64) -> Option<u64> {
        if !matches!(size, 1 | 2 | 4 | 8) {
            return None;
        }
        let offset = address?.checked_sub(self.image_base)?;
        let mut value = 0u64;
        for byte in 0..size {
            value |= u64::from(*self.fixed_header.get(&(offset + byte))?) << (byte * 8);
        }
        Some(value)
    }
    pub fn guest_write(
        &mut self,
        expressions: &mut Expressions,
        address: Id,
        size: u64,
        value: Id,
        numeric: Value,
        segment: R,
    ) {
        // Native addresses derived from ImageBase retain their guest identity,
        // even if their numeric value overlaps the analysis bytecode mapping.
        let value = if size == 8
            && !expressions.relocatable(value)
            && let Some(pointer) = numeric.get()
            && let Some(&(_, _, origin)) = self
                .code_ranges
                .iter()
                .find(|&&(base, length, _)| pointer.wrapping_sub(base) < length)
        {
            expressions.intern(Expr::RuntimeData(pointer - origin))
        } else {
            value
        };
        self.stores.push(Store {
            address,
            value,
            width: size * 8,
            segment,
            epoch: self.epoch,
        });
        self.epoch += 1;
        self.guest_memory.clear();
        self.guest_memory.insert((address, size), (value, numeric));
    }

    pub fn write(&mut self, expressions: &mut Expressions, address: u64, size: u64, value: Id) {
        if size == 8 && self.words.get(&address) == Some(&value) {
            return;
        }
        // Keep whole spills as one expression. Materialize only the surviving
        // fragments of an overlapping word, rather than four bytes per spill.
        for offset in 0..size + 7 {
            let start = address.wrapping_sub(7).wrapping_add(offset);
            if let Some(word) = self.words.remove(&start) {
                for byte in 0..8 {
                    let at = start.wrapping_add(byte);
                    if at.wrapping_sub(address) >= size {
                        self.bytes
                            .insert(at, expressions.extract(word, byte * 8, 8));
                    }
                }
            }
        }
        if size == 8 {
            for offset in 0..8 {
                self.bytes.remove(&address.wrapping_add(offset));
                // Keep stable expression numbering for native temp layout.
                expressions.extract(value, offset * 8, 8);
            }
            self.words.insert(address, value);
        } else {
            for offset in 0..size {
                self.bytes.insert(
                    address.wrapping_add(offset),
                    expressions.extract(value, offset * 8, 8),
                );
            }
        }
    }

    pub fn operand(
        &self,
        expressions: &mut Expressions,
        image: &Image,
        i: &Instruction,
        operand: u32,
    ) -> Result<Id> {
        Ok(match i.op_kind(operand) {
            OpKind::Register => self.reg(expressions, i.op_register(operand))?,
            OpKind::Memory => {
                let pointer = self.address(expressions, i)?;
                if let Some(value) =
                    self.header_value(self.numeric_address(i)?, i.memory_size().size() as u64)
                {
                    return Ok(expressions.constant(value));
                }
                if expressions.guest_pointer(pointer) {
                    self.guest_read(
                        expressions,
                        pointer,
                        i.memory_size().size() as u64,
                        i.memory_segment(),
                    )
                    .0
                } else if let Some(address) = self.numeric_address(i)? {
                    self.read(
                        expressions,
                        image,
                        address,
                        i.memory_size().size() as u64,
                        pointer,
                    )?
                } else {
                    expressions.intern(Expr::Load(
                        pointer,
                        x64::width(i, operand)?,
                        i.memory_segment(),
                        self.epoch,
                    ))
                }
            }
            OpKind::NearBranch64 => expressions.constant(i.near_branch64()),
            _ => expressions.constant(i.immediate(operand)),
        })
    }

    fn assign(
        &mut self,
        expressions: &mut Expressions,
        i: &Instruction,
        operand: u32,
        value: Id,
    ) -> Result<()> {
        match i.op_kind(operand) {
            OpKind::Register => self.set_reg(expressions, i.op_register(operand), value),
            OpKind::Memory => {
                let pointer = self.address(expressions, i)?;
                let size = i.memory_size().size() as u64;
                if expressions.guest_pointer(pointer) {
                    let numeric = expressions
                        .value(value)
                        .map_or(Value::UNKNOWN, Value::constant);
                    self.guest_write(
                        expressions,
                        pointer,
                        size,
                        value,
                        numeric,
                        i.memory_segment(),
                    );
                } else if let Some(address) = self.numeric_address(i)? {
                    let value = if self.guest_sp == Some(address) {
                        expressions.intern(Expr::GuestPointer(value))
                    } else {
                        value
                    };
                    self.write(expressions, address, size, value);
                    let internal = (self.stack_start..self.stack_end).contains(&address)
                        || self
                            .internal
                            .iter()
                            .any(|&(start, size)| address.wrapping_sub(start) < size);
                    if !internal {
                        self.stores.push(Store {
                            address: pointer,
                            value,
                            width: size * 8,
                            segment: i.memory_segment(),
                            epoch: self.epoch,
                        });
                        self.epoch += 1;
                    }
                } else {
                    self.stores.push(Store {
                        address: pointer,
                        value,
                        width: size * 8,
                        segment: i.memory_segment(),
                        epoch: self.epoch,
                    });
                    self.epoch += 1;
                }
                Ok(())
            }
            _ => bail!("unsupported lifted destination"),
        }
    }

    fn push(&mut self, expressions: &mut Expressions, value: Id, size: u64) -> Result<()> {
        let esp = self.cpu.registers[4]
            .get()
            .map(|esp| esp.wrapping_sub(size));
        let amount = expressions.constant(size);
        self.registers[4] = expressions.binary(M::Sub, self.registers[4], amount, 64);
        if expressions.guest_pointer(self.registers[4]) {
            let numeric = expressions
                .value(value)
                .map_or(Value::UNKNOWN, Value::constant);
            self.guest_write(expressions, self.registers[4], size, value, numeric, R::SS);
        } else {
            self.write(
                expressions,
                esp.context("unknown private stack pointer")?,
                size,
                value,
            );
        }
        Ok(())
    }

    pub fn step(
        &mut self,
        expressions: &mut Expressions,
        image: &Image,
        i: &Instruction,
    ) -> Result<Option<Self>> {
        let old_stack = self.registers[4];
        let numeric_stack = self.cpu.registers[4].get();
        let guest_address = if i.mnemonic() != M::Lea
            && (0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory)
        {
            let address = self.address(expressions, i)?;
            (expressions.guest_pointer(address)
                || self
                    .header_value(self.numeric_address(i)?, i.memory_size().size() as u64)
                    .is_some())
            .then_some(address)
        } else {
            None
        };
        let numeric_guest_address = if guest_address.is_some() {
            self.numeric_address(i)?
        } else {
            None
        };
        let guest_numeric = guest_address.map(|address| {
            self.header_value(numeric_guest_address, i.memory_size().size() as u64)
                .map(Value::constant)
                .or_else(|| {
                    numeric_guest_address.and_then(|at| {
                        self.guest_values
                            .get(&(at, i.memory_size().size() as u64))
                            .copied()
                    })
                })
                .unwrap_or_else(|| {
                    self.guest_read(
                        expressions,
                        address,
                        i.memory_size().size() as u64,
                        i.memory_segment(),
                    )
                    .1
                })
        });
        let mut updates = Vec::new();
        let old_flags = self.flags;
        let m = i.mnemonic();
        match m {
            M::Mov | M::Movzx | M::Movsx | M::Movsxd => {
                let value = self.operand(expressions, image, i, 1)?;
                let value = if matches!(m, M::Movsx | M::Movsxd) {
                    let width = x64::width(i, 1)?;
                    expressions.unary(M::Movsx, value, width)
                } else {
                    value
                };
                updates.push((0, value));
            }
            M::Lea => {
                let value = self.address(expressions, i)?;
                updates.push((0, value));
            }
            M::Xchg => {
                let a = self.operand(expressions, image, i, 0)?;
                let b = self.operand(expressions, image, i, 1)?;
                // Effective addresses are captured before either register changes.
                if i.op0_kind() == OpKind::Memory || i.op1_kind() == OpKind::Memory {
                    let memory_operand = if i.op0_kind() == OpKind::Memory { 0 } else { 1 };
                    self.assign(
                        expressions,
                        i,
                        memory_operand,
                        if memory_operand == 0 { b } else { a },
                    )?;
                    self.assign(
                        expressions,
                        i,
                        1 - memory_operand,
                        if memory_operand == 0 { a } else { b },
                    )?;
                } else {
                    self.assign(expressions, i, 0, b)?;
                    self.assign(expressions, i, 1, a)?;
                }
            }
            M::Cqo | M::Cdq | M::Cwd => {
                let width = match m {
                    M::Cqo => 64,
                    M::Cdq => 32,
                    _ => 16,
                };
                let low = expressions.extract(self.registers[0], 0, width);
                let count = expressions.constant(width - 1);
                let high = expressions.binary(M::Sar, low, count, width);
                self.set_reg(
                    expressions,
                    match width {
                        64 => R::RDX,
                        32 => R::EDX,
                        _ => R::DX,
                    },
                    high,
                )?;
            }
            M::Div | M::Idiv => {
                let width = x64::width(i, 0)?;
                let low = expressions.extract(self.registers[0], 0, width);
                let high = expressions.extract(self.registers[2], 0, width);
                let divisor = self.operand(expressions, image, i, 0)?;
                let (quotient, remainder) = if let (Some(h), Some(l), Some(d)) = (
                    expressions.value(high),
                    expressions.value(low),
                    expressions.value(divisor),
                ) {
                    let (q, r) = x64::divide(h, l, d, width, m == M::Idiv)?;
                    (expressions.constant(q), expressions.constant(r))
                } else {
                    (
                        expressions.intern(Expr::Divide(
                            high,
                            low,
                            divisor,
                            width,
                            m == M::Idiv,
                            false,
                        )),
                        expressions.intern(Expr::Divide(
                            high,
                            low,
                            divisor,
                            width,
                            m == M::Idiv,
                            true,
                        )),
                    )
                };
                let (a, d) = match width {
                    16 => (R::AX, R::DX),
                    32 => (R::EAX, R::EDX),
                    64 => (R::RAX, R::RDX),
                    _ => bail!("unsupported lifted division width"),
                };
                self.set_reg(expressions, a, quotient)?;
                self.set_reg(expressions, d, remainder)?;
                self.flags = expressions.flags(m, low, divisor, old_flags, width);
            }
            M::Mul => {
                anyhow::ensure!(x64::width(i, 0)? == 64, "unsupported lifted MUL width");
                let a = self.registers[0];
                let b = self.operand(expressions, image, i, 0)?;
                self.registers[0] = expressions.binary(M::Imul, a, b, 64);
                self.registers[2] = expressions.multiply_high(a, b);
                self.flags = expressions.flags(M::Mul, a, b, old_flags, 64);
            }
            M::Add
            | M::Sub
            | M::Xor
            | M::And
            | M::Or
            | M::Cmp
            | M::Test
            | M::Shl
            | M::Shr
            | M::Sar
            | M::Rol
            | M::Ror
            | M::Imul => {
                let width = x64::width(i, 0)?;
                let a =
                    self.operand(expressions, image, i, if i.op_count() == 3 { 1 } else { 0 })?;
                let b =
                    self.operand(expressions, image, i, if i.op_count() == 3 { 2 } else { 1 })?;
                let value = expressions.binary(m, a, b, width);
                self.flags = expressions.flags(m, a, b, old_flags, width);
                if !matches!(m, M::Cmp | M::Test) {
                    updates.push((0, value));
                }
            }
            M::Not | M::Neg | M::Inc | M::Dec | M::Bswap => {
                let width = x64::width(i, 0)?;
                let a = self.operand(expressions, image, i, 0)?;
                let value = expressions.unary(m, a, width);
                if !matches!(m, M::Not | M::Bswap) {
                    let zero = expressions.constant(0);
                    self.flags = expressions.flags(m, a, zero, old_flags, width);
                }
                updates.push((0, value));
            }
            M::Push => {
                let value = self.operand(expressions, image, i, 0)?;
                self.push(expressions, value, (-i.stack_pointer_increment()) as u64)?;
            }
            M::Pop => {
                let size = i.stack_pointer_increment() as u64;
                let value = if expressions.guest_pointer(self.registers[4]) {
                    self.guest_read(expressions, self.registers[4], size, R::SS)
                        .0
                } else {
                    let esp = self.cpu.esp()?;
                    self.read(expressions, image, esp, size, self.registers[4])?
                };
                let size = expressions.constant(size);
                self.registers[4] = expressions.binary(M::Add, self.registers[4], size, 64);
                updates.push((0, value));
            }
            M::Pushfq | M::Pushf => {
                self.push(expressions, self.flags, if m == M::Pushfq { 8 } else { 2 })?;
            }
            M::Popfq | M::Popf => {
                let size = if m == M::Popfq { 8 } else { 2 };
                let value = if expressions.guest_pointer(self.registers[4]) {
                    self.guest_read(expressions, self.registers[4], size, R::SS)
                        .0
                } else {
                    self.read(expressions, image, self.cpu.esp()?, size, self.registers[4])?
                };
                self.flags = expressions.insert(self.flags, value, 0, size * 8);
                let size = expressions.constant(size);
                self.registers[4] = expressions.binary(M::Add, self.registers[4], size, 64);
            }
            M::Call => {
                let next = expressions.constant(i.next_ip());
                self.push(expressions, next, 8)?;
            }
            M::Ret => {
                let consumed = if i.op_count() > 0 {
                    i.immediate16() as u64
                } else {
                    0
                };
                let size = expressions.constant(8 + consumed);
                self.registers[4] = expressions.binary(M::Add, self.registers[4], size, 64);
            }
            M::Nop
            | M::Jmp
            | M::Je
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
            | M::Jg => {}
            M::Clc | M::Stc | M::Cmc => {
                let mask = expressions.constant(if m == M::Clc { !1 } else { 1 });
                self.flags = expressions.binary(
                    if m == M::Clc {
                        M::And
                    } else if m == M::Stc {
                        M::Or
                    } else {
                        M::Xor
                    },
                    old_flags,
                    mask,
                    64,
                );
            }
            _ => bail!("unsupported lifted instruction {m:?} at {:#x}", i.ip()),
        }
        for (operand, value) in updates {
            self.assign(expressions, i, operand, value)?;
        }
        let conditional = i.flow_control() == iced_x86::FlowControl::ConditionalBranch;
        if conditional
            && expressions.depends_stack(old_flags)
            && expressions.condition(old_flags, m).is_none()
        {
            self.cpu.flags = Value::unknown_flags();
        }
        let guest_stack = expressions.guest_pointer(old_stack);
        let branch = if guest_stack
            && matches!(
                m,
                M::Push | M::Pushfq | M::Pushf | M::Pop | M::Popfq | M::Popf | M::Ret
            ) {
            self.cpu.pc = i.next_ip();
            match m {
                M::Pop => {
                    let numeric = self
                        .guest_read(
                            expressions,
                            old_stack,
                            i.stack_pointer_increment() as u64,
                            R::SS,
                        )
                        .1;
                    x64::set_reg(&mut self.cpu, i.op0_register(), numeric)?;
                }
                M::Popfq | M::Popf => self.cpu.flags = Value::unknown_flags(),
                _ => {}
            }
            let delta = i.stack_pointer_increment();
            self.cpu.registers[4] = numeric_stack.map_or(Value::UNKNOWN, |sp| {
                Value::constant(sp.wrapping_add(delta as u64))
            });
            None
        } else if let Some(address) = guest_address {
            let temporary = self.stack_start.wrapping_sub(0x10000);
            let mut modified = *i;
            modified.set_memory_base(R::None);
            modified.set_memory_index(R::None);
            modified.set_memory_displacement64(temporary);
            modified.set_memory_displ_size(8);
            modified.set_segment_prefix(R::None);
            self.cpu.write(
                image,
                temporary,
                i.memory_size().size() as u64,
                guest_numeric.unwrap(),
            );
            let branch = x64::execute(&mut self.cpu, image, &modified)?;
            let value = self
                .cpu
                .read(image, temporary, i.memory_size().size() as u64);
            self.cpu.forget(temporary, i.memory_size().size() as u64);
            if i.op0_kind() == OpKind::Memory && !matches!(m, M::Cmp | M::Test) {
                if let Some(at) = numeric_guest_address {
                    let size = i.memory_size().size() as u64;
                    self.guest_values.retain(|&(base, length), _| {
                        base.wrapping_sub(at) >= size && at.wrapping_sub(base) >= length
                    });
                    self.guest_values.insert((at, size), value);
                } else {
                    self.guest_values.clear();
                }
            }
            if let Some(entry) = self
                .guest_memory
                .get_mut(&(address, i.memory_size().size() as u64))
            {
                entry.1 = value;
            }
            if i.op0_kind() == OpKind::Memory
                && self
                    .stores
                    .last()
                    .is_some_and(|store| !expressions.relocatable(store.value))
                && let Some(pointer) = value.get()
                && let Some(&(_, _, origin)) = self
                    .code_ranges
                    .iter()
                    .find(|&&(base, length, _)| pointer.wrapping_sub(base) < length)
            {
                let continuation = expressions.intern(Expr::RuntimeData(pointer - origin));
                if let Some(store) = self.stores.last_mut() {
                    store.value = continuation;
                }
                if let Some(entry) = self
                    .guest_memory
                    .get_mut(&(address, i.memory_size().size() as u64))
                {
                    entry.0 = continuation;
                }
            }
            branch
        } else if i.op0_kind() == OpKind::Memory
            && self.numeric_address(i)?.is_none()
            && matches!(
                m,
                M::Mov
                    | M::Add
                    | M::Sub
                    | M::Xor
                    | M::And
                    | M::Or
                    | M::Inc
                    | M::Dec
                    | M::Not
                    | M::Neg
            )
        {
            self.cpu.pc = i.next_ip();
            if m != M::Mov && m != M::Not {
                self.cpu.flags = Value::unknown_flags();
            }
            None
        } else if i.op1_kind() == OpKind::Memory
            && matches!(i.memory_segment(), R::FS | R::GS)
            && matches!(m, M::Mov | M::Movzx | M::Movsx | M::Movsxd)
        {
            x64::set_reg(&mut self.cpu, i.op0_register(), Value::UNKNOWN)?;
            self.cpu.pc = i.next_ip();
            None
        } else {
            x64::execute(&mut self.cpu, image, i)?
        };
        if let Some(cpu) = branch {
            let mut other = self.clone();
            other.cpu = cpu;
            if matches!(m, M::Je | M::Jne) {
                self.refine_zero(expressions, image, old_flags, m == M::Jne);
                other.refine_zero(expressions, image, old_flags, m == M::Je);
            }
            other.conditions.push(Predicate {
                flags: old_flags,
                op: m,
                taken: true,
                epoch: self.epoch,
            });
            self.conditions.push(Predicate {
                flags: old_flags,
                op: m,
                taken: false,
                epoch: self.epoch,
            });
            Ok(Some(other))
        } else {
            Ok(None)
        }
    }
}
