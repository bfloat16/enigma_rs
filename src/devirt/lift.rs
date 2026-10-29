//! Symbolic handler execution. Internal VM memory becomes expressions; host
//! memory remains an explicit effect. This pass never invokes native callbacks.
use super::{
    ir::{Expr, Expressions, Id},
    static_x86::{self as x86, Image, State, Value},
};
use anyhow::{Context, Result, bail};
use iced_x86::{Instruction, Mnemonic as M, OpKind, Register as R};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Store {
    pub address: Id,
    pub value: Id,
    pub width: u32,
    pub segment: R,
    pub epoch: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Predicate {
    pub flags: Id,
    pub op: M,
    pub taken: bool,
    pub epoch: u32,
}

#[derive(Clone)]
pub(crate) struct StateExpressions {
    pub cpu: State,
    pub registers: [Id; 8],
    pub flags: Id,
    pub bytes: HashMap<u32, Id>,
    pub words: HashMap<u32, Id>,
    pub stores: Vec<Store>,
    pub stack_start: u32,
    pub stack_end: u32,
    pub internal: Vec<(u32, u32)>,
    pub conditions: Vec<Predicate>,
    pub epoch: u32,
    pub guest_sp: Option<u32>,
    pub guest_memory: HashMap<(Id, u32), (Id, Value)>,
    pub code_ranges: Vec<(u32, u32, u32)>,
    pub guest_values: HashMap<(u32, u32), Value>,
    pub image_signature: u16,
    pub initializer_words: HashMap<u32, Id>,
    pub image_base: u32,
    pub fixed_header: Arc<HashMap<u32, u8>>,
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
                let numeric = self.cpu.read(image, at, 4).assume_zero(zero);
                self.cpu.write(image, at, 4, numeric);
            }
        }
    }
    pub fn new(
        cpu: State,
        expressions: &mut Expressions,
        stack_start: u32,
        stack_end: u32,
    ) -> Self {
        let registers = std::array::from_fn(|r| expressions.input(r as u32));
        let flags = expressions.input(8);
        Self {
            cpu,
            registers,
            flags,
            bytes: HashMap::new(),
            words: HashMap::new(),
            stores: Vec::new(),
            stack_start,
            stack_end,
            internal: Vec::new(),
            conditions: Vec::new(),
            epoch: 0,
            guest_sp: None,
            guest_memory: HashMap::new(),
            code_ranges: Vec::new(),
            guest_values: HashMap::new(),
            image_signature: 0,
            initializer_words: HashMap::new(),
            image_base: 0,
            fixed_header: Arc::default(),
        }
    }

    pub fn reg(&self, expressions: &mut Expressions, register: R) -> Result<Id> {
        if register == R::None {
            return Ok(expressions.constant(0));
        }
        let (index, offset, width) = x86::register(register)?;
        Ok(expressions.extract(self.registers[index], offset, width))
    }

    fn set_reg(&mut self, expressions: &mut Expressions, register: R, value: Id) -> Result<()> {
        let (index, offset, width) = x86::register(register)?;
        self.registers[index] = expressions.insert(self.registers[index], value, offset, width);
        Ok(())
    }

    pub fn address(&self, expressions: &mut Expressions, i: &Instruction) -> Result<Id> {
        let base = self.reg(expressions, i.memory_base())?;
        let index = self.reg(expressions, i.memory_index())?;
        let scale = expressions.constant(i.memory_index_scale());
        let index = expressions.binary(M::Imul, index, scale, 32);
        let base = expressions.binary(M::Add, base, index, 32);
        let displacement = expressions.constant(i.memory_displacement32());
        Ok(expressions.binary(M::Add, base, displacement, 32))
    }

    fn numeric_address(&self, i: &Instruction) -> Result<Option<u32>> {
        if matches!(i.memory_segment(), R::FS | R::GS) {
            return Ok(None);
        }
        Ok(x86::address(&self.cpu, i)?.get())
    }

    pub fn read(
        &self,
        expressions: &mut Expressions,
        image: &Image,
        address: u32,
        size: u32,
        pointer: Id,
    ) -> Id {
        if let Some(value) = self.header_value(Some(address), size) {
            return expressions.constant(value);
        }
        if expressions.guest_pointer(pointer) {
            return self.guest_read(expressions, pointer, size, R::DS).0;
        }
        if let Some(&word) = self.words.get(&address) {
            if let Some(value) = self.cpu.read(image, address, size).get()
                && !expressions.depends_stack(word)
                && !expressions.relocatable(word)
            {
                return expressions.constant(value);
            }
            return expressions.extract(word, 0, size * 8);
        }
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
            return expressions.extract(source, 0, size * 8);
        }
        let mut result = expressions.constant(0);
        for offset in 0..size {
            let at = address.wrapping_add(offset);
            let byte = if let Some(&value) = self.bytes.get(&at) {
                value
            } else if let Some(value) = self.cpu.read(image, at, 1).get() {
                expressions.constant(value)
            } else {
                expressions.input(0x80000000 | at)
            };
            result = expressions.insert(result, byte, offset * 8, 8);
        }
        result
    }
    pub fn guest_read(
        &self,
        expressions: &mut Expressions,
        address: Id,
        size: u32,
        segment: R,
    ) -> (Id, Value) {
        if let Some(&value) = self.guest_memory.get(&(address, size)) {
            return value;
        }
        if size == 2 && matches!(expressions.node(address), Expr::ImageBase) {
            let value = u32::from(self.image_signature);
            return (expressions.constant(value), Value::constant(value));
        }
        (
            expressions.intern(Expr::Load(address, size * 8, segment, self.epoch)),
            Value::UNKNOWN,
        )
    }

    fn header_value(&self, address: Option<u32>, size: u32) -> Option<u32> {
        if !matches!(size, 1 | 2 | 4) {
            return None;
        }
        let offset = address?.checked_sub(self.image_base)?;
        let mut value = 0u32;
        for byte in 0..size {
            value |= u32::from(*self.fixed_header.get(&(offset + byte))?) << (byte * 8);
        }
        Some(value)
    }
    pub fn guest_write(
        &mut self,
        expressions: &mut Expressions,
        address: Id,
        size: u32,
        value: Id,
        numeric: Value,
        segment: R,
    ) {
        // Native addresses derived from ImageBase retain their guest identity,
        // even if their numeric value overlaps the analysis bytecode mapping.
        let value = if size == 4
            && !expressions.relocatable(value)
            && let Some(pointer) = numeric.get()
            && let Some(&(_, _, origin)) = self
                .code_ranges
                .iter()
                .find(|&&(base, length, _)| pointer.wrapping_sub(base) < length)
        {
            expressions.intern(Expr::Bytecode(pointer - origin))
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

    pub fn write(&mut self, expressions: &mut Expressions, address: u32, size: u32, value: Id) {
        self.words
            .retain(|&at, _| at.wrapping_sub(address) >= size && address.wrapping_sub(at) >= 4);
        if size == 4 {
            self.words.insert(address, value);
        }
        for offset in 0..size {
            self.bytes.insert(
                address.wrapping_add(offset),
                expressions.extract(value, offset * 8, 8),
            );
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
                    self.header_value(self.numeric_address(i)?, i.memory_size().size() as u32)
                {
                    return Ok(expressions.constant(value));
                }
                if expressions.guest_pointer(pointer) {
                    self.guest_read(
                        expressions,
                        pointer,
                        i.memory_size().size() as u32,
                        i.memory_segment(),
                    )
                    .0
                } else if let Some(address) = self.numeric_address(i)? {
                    self.read(
                        expressions,
                        image,
                        address,
                        i.memory_size().size() as u32,
                        pointer,
                    )
                } else {
                    expressions.intern(Expr::Load(
                        pointer,
                        x86::width(i, operand)?,
                        i.memory_segment(),
                        self.epoch,
                    ))
                }
            }
            OpKind::NearBranch32 => expressions.constant(i.near_branch32()),
            _ => expressions.constant(i.immediate(operand) as u32),
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
                let size = i.memory_size().size() as u32;
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

    fn push(&mut self, expressions: &mut Expressions, value: Id, size: u32) -> Result<()> {
        let esp = self.cpu.registers[4]
            .get()
            .map(|esp| esp.wrapping_sub(size));
        let amount = expressions.constant(size);
        self.registers[4] = expressions.binary(M::Sub, self.registers[4], amount, 32);
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
                    .header_value(self.numeric_address(i)?, i.memory_size().size() as u32)
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
            self.header_value(numeric_guest_address, i.memory_size().size() as u32)
                .map(Value::constant)
                .or_else(|| {
                    numeric_guest_address.and_then(|at| {
                        self.guest_values
                            .get(&(at, i.memory_size().size() as u32))
                            .copied()
                    })
                })
                .unwrap_or_else(|| {
                    self.guest_read(
                        expressions,
                        address,
                        i.memory_size().size() as u32,
                        i.memory_segment(),
                    )
                    .1
                })
        });
        let mut updates = Vec::new();
        let old_flags = self.flags;
        let m = i.mnemonic();
        match m {
            M::Mov | M::Movzx | M::Movsx => {
                let value = self.operand(expressions, image, i, 1)?;
                let value = if m == M::Movsx {
                    let width = x86::width(i, 1)?;
                    expressions.intern(Expr::Unary(m, value, width))
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
            M::Mul => {
                anyhow::ensure!(x86::width(i, 0)? == 32, "unsupported lifted MUL width");
                let a = self.registers[0];
                let b = self.operand(expressions, image, i, 0)?;
                self.registers[0] = expressions.binary(M::Imul, a, b, 32);
                self.registers[2] = expressions.multiply_high(a, b);
                self.flags = expressions.flags(M::Mul, a, b, old_flags, 32);
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
                let width = x86::width(i, 0)?;
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
                let width = x86::width(i, 0)?;
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
                self.push(expressions, value, (-i.stack_pointer_increment()) as u32)?;
            }
            M::Pop => {
                let size = i.stack_pointer_increment() as u32;
                let value = if expressions.guest_pointer(self.registers[4]) {
                    self.guest_read(expressions, self.registers[4], size, R::SS)
                        .0
                } else {
                    let esp = self.cpu.esp()?;
                    self.read(expressions, image, esp, size, self.registers[4])
                };
                let size = expressions.constant(size);
                self.registers[4] = expressions.binary(M::Add, self.registers[4], size, 32);
                updates.push((0, value));
            }
            M::Pushad => {
                let registers = self.registers;
                if expressions.guest_pointer(self.registers[4]) {
                    for value in registers {
                        self.push(expressions, value, 4)?;
                    }
                } else {
                    let esp = self.cpu.esp()?;
                    for (index, value) in registers.into_iter().enumerate() {
                        self.write(
                            expressions,
                            esp.wrapping_sub((index as u32 + 1) * 4),
                            4,
                            value,
                        );
                    }
                    let size = expressions.constant(32);
                    self.registers[4] = expressions.binary(M::Sub, self.registers[4], size, 32);
                }
            }
            M::Popad => {
                let esp = self.cpu.registers[4].get();
                for index in (0..8).rev() {
                    if index != 4 {
                        let pointer = expressions.constant((7 - index as u32) * 4);
                        let pointer = expressions.binary(M::Add, self.registers[4], pointer, 32);
                        self.registers[index] = if expressions.guest_pointer(pointer) {
                            self.guest_read(expressions, pointer, 4, R::SS).0
                        } else {
                            self.read(
                                expressions,
                                image,
                                esp.context("unknown private POPAD stack")?
                                    + (7 - index as u32) * 4,
                                4,
                                pointer,
                            )
                        };
                    }
                }
                let size = expressions.constant(32);
                self.registers[4] = expressions.binary(M::Add, self.registers[4], size, 32);
            }
            M::Pushfd | M::Pushf => {
                self.push(expressions, self.flags, if m == M::Pushfd { 4 } else { 2 })?;
            }
            M::Popfd | M::Popf => {
                let size = if m == M::Popfd { 4 } else { 2 };
                let value = if expressions.guest_pointer(self.registers[4]) {
                    self.guest_read(expressions, self.registers[4], size, R::SS)
                        .0
                } else {
                    self.read(expressions, image, self.cpu.esp()?, size, self.registers[4])
                };
                self.flags = expressions.insert(self.flags, value, 0, size * 8);
                let size = expressions.constant(size);
                self.registers[4] = expressions.binary(M::Add, self.registers[4], size, 32);
            }
            M::Call => {
                let next = expressions.constant(i.next_ip32());
                self.push(expressions, next, 4)?;
            }
            M::Ret => {
                let consumed = if i.op_count() > 0 {
                    i.immediate16() as u32
                } else {
                    0
                };
                let size = expressions.constant(4 + consumed);
                self.registers[4] = expressions.binary(M::Add, self.registers[4], size, 32);
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
                    32,
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
                M::Push
                    | M::Pushad
                    | M::Pushfd
                    | M::Pushf
                    | M::Pop
                    | M::Popad
                    | M::Popfd
                    | M::Popf
                    | M::Ret
            ) {
            self.cpu.pc = i.next_ip32();
            match m {
                M::Pop => {
                    let numeric = self
                        .guest_read(
                            expressions,
                            old_stack,
                            i.stack_pointer_increment() as u32,
                            R::SS,
                        )
                        .1;
                    x86::set_reg(&mut self.cpu, i.op0_register(), numeric)?;
                }
                M::Popad => {
                    for n in 0..8 {
                        if n != 4 {
                            self.cpu.registers[n] = Value::UNKNOWN;
                        }
                    }
                }
                M::Popfd | M::Popf => self.cpu.flags = Value::unknown_flags(),
                _ => {}
            }
            let delta = i.stack_pointer_increment();
            self.cpu.registers[4] = numeric_stack.map_or(Value::UNKNOWN, |sp| {
                Value::constant(sp.wrapping_add(delta as u32))
            });
            None
        } else if let Some(address) = guest_address {
            let temporary = self.stack_start.wrapping_sub(0x10000);
            let mut modified = *i;
            modified.set_memory_base(R::None);
            modified.set_memory_index(R::None);
            modified.set_memory_displacement64(temporary as u64);
            modified.set_memory_displ_size(4);
            modified.set_segment_prefix(R::None);
            let mut cpu = self.cpu.clone();
            cpu.write(
                image,
                temporary,
                i.memory_size().size() as u32,
                guest_numeric.unwrap(),
            );
            let branch = x86::execute(&mut cpu, image, &modified)?;
            let value = cpu.read(image, temporary, i.memory_size().size() as u32);
            cpu.forget(temporary, i.memory_size().size() as u32);
            self.cpu = cpu;
            if i.op0_kind() == OpKind::Memory && !matches!(m, M::Cmp | M::Test) {
                if let Some(at) = numeric_guest_address {
                    let size = i.memory_size().size() as u32;
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
                .get_mut(&(address, i.memory_size().size() as u32))
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
                let continuation = expressions.intern(Expr::Bytecode(pointer - origin));
                if let Some(store) = self.stores.last_mut() {
                    store.value = continuation;
                }
                if let Some(entry) = self
                    .guest_memory
                    .get_mut(&(address, i.memory_size().size() as u32))
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
            self.cpu.pc = i.next_ip32();
            if m != M::Mov && m != M::Not {
                self.cpu.flags = Value::unknown_flags();
            }
            None
        } else if i.op1_kind() == OpKind::Memory
            && matches!(i.memory_segment(), R::FS | R::GS)
            && matches!(m, M::Mov | M::Movzx | M::Movsx)
        {
            x86::set_reg(&mut self.cpu, i.op0_register(), Value::UNKNOWN)?;
            self.cpu.pc = i.next_ip32();
            None
        } else {
            x86::execute(&mut self.cpu, image, i)?
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
