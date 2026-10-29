//! Bit-vector expressions used to lift a handler before choosing native opcodes.
use iced_x86::Mnemonic;
use std::collections::HashMap;

pub(crate) type Id = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Expr {
    Constant(u32),
    Input(u32),
    Cell(u32),
    Function(u32),
    ImageBase,
    GuestPointer(Id),
    PrivateAddress(u32),
    Continuation(u32),
    Bytecode(u32),
    Extract(Id, u32, u32),
    Insert(Id, Id, u32, u32),
    Unary(Mnemonic, Id, u32),
    Binary(Mnemonic, Id, Id, u32),
    Flags(Mnemonic, Id, Id, Id, u32),
    Load(Id, u32, iced_x86::Register, u32),
}

#[derive(Default)]
pub(crate) struct Expressions {
    nodes: Vec<Expr>,
    index: HashMap<Expr, Id>,
    private_ranges: Vec<(u32, u32)>,
    next_input: u32,
}

impl Expressions {
    pub fn private_range(&mut self, start: u32, size: u32) {
        self.private_ranges.push((start, size));
    }

    fn private_offset(&mut self, value: u32) -> Id {
        if self
            .private_ranges
            .iter()
            .any(|&(start, size)| value.wrapping_sub(start) < size)
        {
            self.intern(Expr::PrivateAddress(value))
        } else {
            self.constant(value)
        }
    }
    pub fn node(&self, id: Id) -> &Expr {
        &self.nodes[id as usize]
    }

    pub fn intern(&mut self, expr: Expr) -> Id {
        if let Some(&id) = self.index.get(&expr) {
            return id;
        }
        let id = self.nodes.len() as Id;
        self.nodes.push(expr);
        self.index.insert(expr, id);
        id
    }

    pub fn constant(&mut self, value: u32) -> Id {
        self.intern(Expr::Constant(value))
    }

    pub fn value(&self, id: Id) -> Option<u32> {
        match self.node(id) {
            Expr::Constant(value) => Some(*value),
            _ => None,
        }
    }
    pub fn guest_pointer(&self, id: Id) -> bool {
        match *self.node(id) {
            Expr::GuestPointer(_) | Expr::ImageBase => true,
            Expr::Binary(_, a, b, _) => self.guest_pointer(a) || self.guest_pointer(b),
            Expr::Insert(a, b, _, _) => self.guest_pointer(a) || self.guest_pointer(b),
            Expr::Unary(_, a, _) | Expr::Extract(a, _, _) => self.guest_pointer(a),
            _ => false,
        }
    }

    pub fn input(&mut self, name: u32) -> Id {
        self.intern(Expr::Input(name))
    }
    pub fn fresh_input(&mut self) -> Id {
        let name = 0x10000 + self.next_input;
        self.next_input += 1;
        self.input(name)
    }

    /// Address-bearing expressions must keep their linker identity even when
    /// the analysis machine happens to know an address in its private arena.
    pub fn relocatable(&self, id: Id) -> bool {
        match *self.node(id) {
            Expr::Function(_) | Expr::ImageBase | Expr::Continuation(_) | Expr::Bytecode(_) => true,
            Expr::GuestPointer(a) | Expr::Extract(a, _, _) | Expr::Unary(_, a, _) => {
                self.relocatable(a)
            }
            Expr::Insert(a, b, _, _) | Expr::Binary(_, a, b, _) => {
                self.relocatable(a) || self.relocatable(b)
            }
            _ => false,
        }
    }

    pub fn stack_offset(&self, id: Id) -> Option<i32> {
        match *self.node(id) {
            Expr::Input(4) => Some(0),
            Expr::GuestPointer(value) => self.stack_offset(value),
            Expr::Binary(Mnemonic::Add, a, b, 32) => self
                .stack_offset(a)
                .zip(self.value(b))
                .map(|(a, b)| a.wrapping_add(b as i32)),
            Expr::Binary(Mnemonic::Sub, a, b, 32) => self
                .stack_offset(a)
                .zip(self.value(b))
                .map(|(a, b)| a.wrapping_sub(b as i32)),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn depends_stack(&self, id: Id) -> bool {
        match *self.node(id) {
            Expr::Input(4) | Expr::ImageBase | Expr::GuestPointer(_) => true,
            Expr::Extract(a, _, _) | Expr::Unary(_, a, _) | Expr::Load(a, _, _, _) => {
                self.depends_stack(a)
            }
            Expr::Insert(a, b, _, _) | Expr::Binary(_, a, b, _) => {
                self.depends_stack(a) || self.depends_stack(b)
            }
            Expr::Flags(_, a, b, c, _) => {
                self.depends_stack(a) || self.depends_stack(b) || self.depends_stack(c)
            }
            _ => false,
        }
    }

    pub fn flag(&self, id: Id, bit: u32) -> Option<bool> {
        use Mnemonic as M;
        match *self.node(id) {
            Expr::Constant(value) => Some(value & bit != 0),
            Expr::Input(8) if bit == 2 => Some(true),
            Expr::Binary(M::And, a, b, _) => match (self.flag(a, bit), self.flag(b, bit)) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(a), Some(b)) => Some(a & b),
                _ => None,
            },
            Expr::Binary(M::Or, a, b, _) => match (self.flag(a, bit), self.flag(b, bit)) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(a), Some(b)) => Some(a | b),
                _ => None,
            },
            Expr::Binary(M::Xor, a, b, _) => {
                self.flag(a, bit).zip(self.flag(b, bit)).map(|(a, b)| a ^ b)
            }
            Expr::Flags(op, a, b, old, width) => {
                let a_value = self.value(a);
                let b_value = self.value(b);
                let arithmetic = matches!(
                    op,
                    M::Add
                        | M::Sub
                        | M::Cmp
                        | M::And
                        | M::Or
                        | M::Xor
                        | M::Test
                        | M::Neg
                        | M::Inc
                        | M::Dec
                );
                if !arithmetic {
                    if matches!(op, M::Rol | M::Ror | M::Shl | M::Shr | M::Sar) {
                        let count = b_value? & 31;
                        if count == 0 || matches!(op, M::Rol | M::Ror) && count % width == 0 {
                            return self.flag(old, bit);
                        }
                        let a = a_value? & mask(width);
                        let n = if matches!(op, M::Rol | M::Ror) {
                            count % width
                        } else {
                            count
                        };
                        let result = match op {
                            M::Shl => a.wrapping_shl(n) & mask(width),
                            M::Shr => a >> n,
                            M::Sar => {
                                (((a << (32 - width)) as i32 >> (32 - width)) >> n) as u32
                                    & mask(width)
                            }
                            M::Rol => ((a << n) | (a >> (width - n))) & mask(width),
                            M::Ror => ((a >> n) | (a << (width - n))) & mask(width),
                            _ => unreachable!(),
                        };
                        let sign = 1u32 << (width - 1);
                        let cf = match op {
                            M::Rol => Some(result & 1 != 0),
                            M::Ror => Some(result & sign != 0),
                            M::Sar if n >= width => Some(a & sign != 0),
                            M::Shl if n <= width => Some(a & (1 << (width - n)) != 0),
                            M::Shr | M::Sar if n <= width => Some(a & (1 << (n - 1)) != 0),
                            _ => None,
                        };
                        return match bit {
                            1 => cf,
                            2048 if count == 1 => match op {
                                M::Rol | M::Shl => cf.map(|c| (result & sign != 0) ^ c),
                                M::Ror => Some(
                                    ((result >> (width - 1)) ^ (result >> (width - 2))) & 1 != 0,
                                ),
                                M::Shr => Some(a & sign != 0),
                                M::Sar => Some(false),
                                _ => None,
                            },
                            2048 => None,
                            4 if !matches!(op, M::Rol | M::Ror) => {
                                Some((result & 255).count_ones().is_multiple_of(2))
                            }
                            64 if !matches!(op, M::Rol | M::Ror) => Some(result == 0),
                            128 if !matches!(op, M::Rol | M::Ror) => Some(result & sign != 0),
                            16 if !matches!(op, M::Rol | M::Ror) => None,
                            _ => self.flag(old, bit),
                        };
                    }
                    if op == M::Mul && matches!(bit, 1 | 2048) {
                        let (a, b) = a_value.zip(b_value)?;
                        return Some((a as u64 * b as u64) >> width != 0);
                    }
                    if op == M::Imul && matches!(bit, 1 | 2048) {
                        let (a, b) = a_value.zip(b_value)?;
                        let a = ((a << (32 - width)) as i32 >> (32 - width)) as i64;
                        let b = ((b << (32 - width)) as i32 >> (32 - width)) as i64;
                        let p = a * b;
                        return Some(p < -(1i64 << (width - 1)) || p >= (1i64 << (width - 1)));
                    }
                    return None;
                }
                if bit == 1 && matches!(op, M::Inc | M::Dec) {
                    return self.flag(old, bit);
                }
                if !matches!(bit, 1 | 4 | 16 | 64 | 128 | 2048) {
                    return self.flag(old, bit);
                }
                if matches!(op, M::And | M::Or | M::Xor | M::Test) && matches!(bit, 1 | 2048) {
                    return Some(false);
                }
                if a == b
                    && matches!(op, M::Sub | M::Cmp | M::Xor)
                    && matches!(bit, 1 | 4 | 16 | 64 | 128 | 2048)
                {
                    return Some(matches!(bit, 4 | 64));
                }
                let (mut a, mut b) = a_value.zip(b_value)?;
                let operand = a;
                if matches!(op, M::Inc | M::Dec) {
                    b = 1;
                }
                if op == M::Neg {
                    a = 0;
                    b = operand;
                }
                let result = match op {
                    M::Add => a.wrapping_add(b),
                    M::Sub | M::Cmp => a.wrapping_sub(b),
                    M::And | M::Test => a & b,
                    M::Or => a | b,
                    M::Xor => a ^ b,
                    M::Neg => operand.wrapping_neg(),
                    M::Inc => operand.wrapping_add(1),
                    M::Dec => operand.wrapping_sub(1),
                    _ => return None,
                } & mask(width);
                let sign = 1 << (width - 1);
                Some(match bit {
                    64 => result == 0,
                    128 => result & sign != 0,
                    4 => (result & 255).count_ones().is_multiple_of(2),
                    1 => {
                        if matches!(op, M::Add | M::Inc) {
                            a as u64 + b as u64 > mask(width) as u64
                        } else if op == M::Neg {
                            operand != 0
                        } else {
                            a < b
                        }
                    }
                    16 => (a ^ b ^ result) & 16 != 0,
                    2048 => {
                        if matches!(op, M::Add | M::Inc) {
                            !(a ^ b) & (a ^ result) & sign != 0
                        } else {
                            (a ^ b) & (a ^ result) & sign != 0
                        }
                    }
                    _ => return None,
                })
            }
            _ => None,
        }
    }

    pub fn condition(&self, flags: Id, op: Mnemonic) -> Option<bool> {
        use Mnemonic as M;
        let flag = |bit| self.flag(flags, bit);
        let not = |v: Option<bool>| v.map(|v| !v);
        let or = |a, b| match (a, b) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(a), Some(b)) => Some(a | b),
            _ => None,
        };
        let signed = flag(128).zip(flag(2048)).map(|(s, o)| s ^ o);
        match op {
            M::Je => flag(64),
            M::Jne => not(flag(64)),
            M::Jb => flag(1),
            M::Jae => not(flag(1)),
            M::Jbe => or(flag(1), flag(64)),
            M::Ja => not(or(flag(1), flag(64))),
            M::Js => flag(128),
            M::Jns => not(flag(128)),
            M::Jo => flag(2048),
            M::Jno => not(flag(2048)),
            M::Jp => flag(4),
            M::Jnp => not(flag(4)),
            M::Jl => signed,
            M::Jge => not(signed),
            M::Jle => or(signed, flag(64)),
            M::Jg => not(or(signed, flag(64))),
            _ => None,
        }
    }

    /// Value whose zero-ness defines ZF. Follow flag masking, not arbitrary
    /// data expressions: preserved flags must not inherit a stale TEST.
    pub fn zero_test(&self, flags: Id) -> Option<Id> {
        use Mnemonic as M;
        match *self.node(flags) {
            Expr::Flags(M::Test, a, b, _, 32) if a == b => Some(a),
            Expr::Flags(M::Cmp, a, b, _, 32) if self.value(b) == Some(0) => Some(a),
            Expr::Binary(M::And, a, b, _) if self.value(b).is_some_and(|v| v & 64 != 0) => {
                self.zero_test(a)
            }
            Expr::Binary(M::Or, a, b, _) => {
                if self.flag(a, 64) == Some(false) {
                    self.zero_test(b)
                } else if self.flag(b, 64) == Some(false) {
                    self.zero_test(a)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn flags(&mut self, op: Mnemonic, a: Id, b: Id, old: Id, width: u32) -> Id {
        use Mnemonic as M;
        let shift = matches!(op, M::Shl | M::Shr | M::Sar | M::Rol | M::Ror);
        let count = self.value(b).map(|n| n & 31);
        if shift && count.is_some_and(|n| n == 0 || matches!(op, M::Rol | M::Ror) && n % width == 0)
        {
            return old;
        }
        let mask = match op {
            M::Inc | M::Dec => 0x8d4,
            M::Rol | M::Ror => 0x801,
            _ => 0x8d5,
        };
        let read = if shift && count.is_none() { mask } else { 0 };
        let read_mask = self.constant(read);
        let incoming = self.binary(M::And, old, read_mask, 32);
        let written = self.intern(Expr::Flags(op, a, b, incoming, width));
        let mask_id = self.constant(mask);
        let written = self.binary(M::And, written, mask_id, 32);
        let preserved_mask = self.constant(!mask);
        let preserved = self.binary(M::And, old, preserved_mask, 32);
        self.binary(M::Or, preserved, written, 32)
    }

    /// Upper 32 bits of an unsigned product, using carry-safe 16-bit limbs.
    pub fn multiply_high(&mut self, a: Id, b: Id) -> Id {
        use Mnemonic as M;
        let mask = self.constant(0xffff);
        let shift = self.constant(16);
        let al = self.binary(M::And, a, mask, 32);
        let ah = self.binary(M::Shr, a, shift, 32);
        let bl = self.binary(M::And, b, mask, 32);
        let bh = self.binary(M::Shr, b, shift, 32);
        let low = self.binary(M::Imul, al, bl, 32);
        let carry = self.binary(M::Shr, low, shift, 32);
        let cross = self.binary(M::Imul, ah, bl, 32);
        let cross = self.binary(M::Add, cross, carry, 32);
        let carry = self.binary(M::Shr, cross, shift, 32);
        let tail = self.binary(M::And, cross, mask, 32);
        let other = self.binary(M::Imul, al, bh, 32);
        let other = self.binary(M::Add, other, tail, 32);
        let other = self.binary(M::Shr, other, shift, 32);
        let high = self.binary(M::Imul, ah, bh, 32);
        let high = self.binary(M::Add, high, carry, 32);
        self.binary(M::Add, high, other, 32)
    }

    pub fn extract(&mut self, id: Id, offset: u32, width: u32) -> Id {
        if offset == 0 && width == 32 {
            return id;
        }
        if let Some(value) = self.value(id) {
            return self.constant((value >> offset) & mask(width));
        }
        if let Expr::Binary(op, a, b, _) = *self.node(id)
            && matches!(op, Mnemonic::And | Mnemonic::Or | Mnemonic::Xor)
        {
            let a = self.extract(a, offset, width);
            let b = self.extract(b, offset, width);
            return self.binary(op, a, b, width);
        }
        if let Expr::Insert(base, part, at, size) = *self.node(id) {
            if offset == at && width == size {
                return self.extract(part, 0, width);
            }
            if offset + width <= at || offset >= at + size {
                return self.extract(base, offset, width);
            }
        }
        if let Expr::Extract(base, at, size) = *self.node(id)
            && offset + width <= size
        {
            return self.extract(base, at + offset, width);
        }
        self.intern(Expr::Extract(id, offset, width))
    }

    pub fn insert(&mut self, base: Id, part: Id, offset: u32, width: u32) -> Id {
        if offset == 0 && width == 32 {
            return part;
        }
        if let (Some(base), Some(part)) = (self.value(base), self.value(part)) {
            let bits = mask(width) << offset;
            return self.constant((base & !bits) | ((part << offset) & bits));
        }
        if let Expr::Extract(source, at, size) = *self.node(part)
            && source == base
            && at == offset
            && size == width
        {
            return base;
        }
        self.intern(Expr::Insert(base, part, offset, width))
    }

    pub fn unary(&mut self, op: Mnemonic, a: Id, width: u32) -> Id {
        use Mnemonic as M;
        if let Some(value) = self.value(a) {
            let result = match op {
                M::Not => !value,
                M::Neg => value.wrapping_neg(),
                M::Bswap => value.swap_bytes(),
                M::Inc => value.wrapping_add(1),
                M::Dec => value.wrapping_sub(1),
                _ => return self.intern(Expr::Unary(op, a, width)),
            };
            return self.constant(result & mask(width));
        }
        if matches!(op, M::Not | M::Neg | M::Bswap)
            && let Expr::Unary(previous, input, size) = *self.node(a)
            && previous == op
            && size == width
        {
            return input;
        }
        self.intern(Expr::Unary(op, a, width))
    }

    pub fn binary(&mut self, op: Mnemonic, mut a: Id, mut b: Id, width: u32) -> Id {
        use Mnemonic as M;
        let bits = mask(width);
        if matches!(op, M::Add | M::Sub)
            && width == 32
            && let Expr::PrivateAddress(address) = *self.node(a)
            && let Some(offset) = self.value(b)
        {
            return self.private_offset(if op == M::Add {
                address.wrapping_add(offset)
            } else {
                address.wrapping_sub(offset)
            });
        }
        if op == M::Sub
            && let (Expr::PrivateAddress(a), Expr::PrivateAddress(b)) = (self.node(a), self.node(b))
        {
            let value = a.wrapping_sub(*b);
            return self.constant(value);
        }
        if matches!(op, M::Sub | M::Cmp)
            && width == 32
            && let Some((a, b)) = self.stack_offset(a).zip(self.stack_offset(b))
        {
            return self.constant(a.wrapping_sub(b) as u32);
        }
        if matches!(op, M::Add | M::And | M::Or | M::Xor | M::Imul)
            && self.value(a).is_some()
            && self.value(b).is_none()
        {
            std::mem::swap(&mut a, &mut b);
        }
        if a == b {
            if matches!(op, M::Sub | M::Cmp | M::Xor) {
                return self.constant(0);
            }
            if matches!(op, M::And | M::Or) {
                return self.extract(a, 0, width);
            }
        }
        if let (Some(left), Some(right)) = (self.value(a), self.value(b)) {
            let n = right & 31;
            let result = match op {
                M::Add => left.wrapping_add(right),
                M::Sub | M::Cmp => left.wrapping_sub(right),
                M::And | M::Test => left & right,
                M::Or => left | right,
                M::Xor => left ^ right,
                M::Imul => left.wrapping_mul(right),
                M::Shl => left.wrapping_shl(n),
                M::Shr => left.wrapping_shr(n),
                M::Sar => (((left << (32 - width)) as i32 >> (32 - width)) >> n) as u32,
                M::Rol | M::Ror => {
                    let n = n % width;
                    if n == 0 {
                        left
                    } else if op == M::Rol {
                        (left << n) | ((left & bits) >> (width - n))
                    } else {
                        ((left & bits) >> n) | (left << (width - n))
                    }
                }
                _ => return self.intern(Expr::Binary(op, a, b, width)),
            };
            return self.constant(result & bits);
        }
        if let Some(b) = self.value(b) {
            if op == M::And {
                let mut unknown = 0u32;
                let mut known = 0u32;
                for bit in 0..width {
                    let flag = 1u32 << bit;
                    if b & flag == 0 {
                        continue;
                    }
                    match self.flag(a, flag) {
                        Some(true) => known |= flag,
                        Some(false) => {}
                        None => unknown |= flag,
                    }
                }
                if unknown == 0 {
                    return self.constant(known);
                }
                if unknown != b {
                    let bits = self.constant(unknown);
                    let remaining = self.binary(M::And, a, bits, width);
                    if known == 0 {
                        return remaining;
                    }
                    let known = self.constant(known);
                    return self.binary(M::Or, remaining, known, width);
                }
            }
            if b == 0
                && matches!(
                    op,
                    M::Add | M::Sub | M::Or | M::Xor | M::Shl | M::Shr | M::Sar | M::Rol | M::Ror
                )
                || b == bits && op == M::And
            {
                return self.extract(a, 0, width);
            }
            if b == 0 && matches!(op, M::And | M::Imul) {
                return self.constant(0);
            }
            if let Expr::Binary(previous, input, c, size) = *self.node(a)
                && size == width
                && let Some(c) = self.value(c)
            {
                if op == M::And && previous == M::And || op == M::Or && previous == M::Or {
                    let constant = self.constant(if op == M::And { b & c } else { b | c });
                    return self.binary(op, input, constant, width);
                }
                if op == M::Xor && previous == M::Xor {
                    let constant = self.constant(b ^ c);
                    return self.binary(M::Xor, input, constant, width);
                }
                if matches!(op, M::Add | M::Sub) && matches!(previous, M::Add | M::Sub) {
                    let left = if previous == M::Sub {
                        c.wrapping_neg()
                    } else {
                        c
                    };
                    let right = if op == M::Sub { b.wrapping_neg() } else { b };
                    let constant = self.constant(left.wrapping_add(right));
                    return self.binary(M::Add, input, constant, width);
                }
                if matches!(op, M::Rol | M::Ror) && matches!(previous, M::Rol | M::Ror) {
                    let left = if previous == M::Ror {
                        -(c as i64)
                    } else {
                        c as i64
                    };
                    let right = if op == M::Ror { -(b as i64) } else { b as i64 };
                    let constant = self.constant((left + right).rem_euclid(width as i64) as u32);
                    return self.binary(M::Rol, input, constant, width);
                }
            }
            if op == M::And
                && let Expr::Binary(M::Or, x, y, size) = *self.node(a)
                && size == width
            {
                let mask = self.constant(b);
                let left = self.binary(M::And, x, mask, width);
                let right = self.binary(M::And, y, mask, width);
                return self.binary(M::Or, left, right, width);
            }
        }
        self.intern(Expr::Binary(op, a, b, width))
    }
}

fn mask(width: u32) -> u32 {
    if width == 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    }
}

pub(crate) fn condition_mask(op: Mnemonic) -> u32 {
    use Mnemonic as M;
    match op {
        M::Je | M::Jne => 64,
        M::Jb | M::Jae => 1,
        M::Jbe | M::Ja => 65,
        M::Js | M::Jns => 128,
        M::Jo | M::Jno => 2048,
        M::Jp | M::Jnp => 4,
        M::Jl | M::Jge => 0x880,
        M::Jle | M::Jg => 0x8c0,
        _ => u32::MAX,
    }
}
