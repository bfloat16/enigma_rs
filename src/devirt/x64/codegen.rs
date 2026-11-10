//! Direct AMD64 instruction selection and encoding. No external compiler.
use super::{
    graph::{End, Graph, Path, Start},
    ir::{Expr, Expressions, Id},
};
use crate::common::io::put_u64_at;
use anyhow::{Context, Result, bail, ensure};
use iced_x86::{
    BlockEncoderOptions, Decoder, DecoderOptions, FlowControl, Mnemonic as M, OpKind,
    Register as R, code_asm::*,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub(crate) struct Program {
    pub bytes: Vec<u8>,
    pub entries: HashMap<Start, u64>,
    pub relocations: Vec<u64>,
}
pub(crate) struct Function<'a> {
    pub arena: &'a Expressions,
    pub blocks: &'a [super::graph::Block],
    pub slots: u64,
    pub start: Start,
    pub guest_stack: u64,
}
impl<'a> From<&'a Graph> for Function<'a> {
    fn from(g: &'a Graph) -> Self {
        Self {
            arena: &g.session.expressions,
            blocks: &g.blocks,
            slots: g.slots,
            start: g.start,
            guest_stack: g.session.stack.saturating_sub(g.session.minimum_stack),
        }
    }
}
/// Only these fields are needed after recovery. Drop the runtime image and
/// execution caches before starting the next continuation.
pub(crate) struct RecoveredFunction {
    arena: Expressions,
    pub blocks: Vec<super::graph::Block>,
    slots: u64,
    start: Start,
    guest_stack: u64,
}
impl From<Graph> for RecoveredFunction {
    fn from(mut graph: Graph) -> Self {
        let map = graph.session.expressions.compact(
            graph
                .blocks
                .iter()
                .flat_map(|b| b.paths.iter().flat_map(roots)),
        );
        let remap = |id: &mut Id| *id = map[*id as usize];
        for path in graph.blocks.iter_mut().flat_map(|b| &mut b.paths) {
            for condition in &mut path.conditions {
                remap(&mut condition.flags);
            }
            for store in &mut path.stores {
                remap(&mut store.address);
                remap(&mut store.value);
            }
            for (_, value) in &mut path.assignments {
                remap(value);
            }
            if let End::Transfer {
                registers,
                flags,
                target,
            } = &mut path.end
            {
                for register in registers {
                    remap(register);
                }
                remap(flags);
                remap(target);
            }
        }
        Self {
            guest_stack: graph
                .session
                .stack
                .saturating_sub(graph.session.minimum_stack),
            arena: graph.session.expressions,
            blocks: graph.blocks,
            slots: graph.slots,
            start: graph.start,
        }
    }
}
impl<'a> From<&'a RecoveredFunction> for Function<'a> {
    fn from(f: &'a RecoveredFunction) -> Self {
        Self {
            arena: &f.arena,
            blocks: &f.blocks,
            slots: f.slots,
            start: f.start,
            guest_stack: f.guest_stack,
        }
    }
}

#[derive(Clone, Copy)]
enum Symbol {
    Image(u64),
    Entry(Start),
}
struct Fixup {
    instruction: usize,
    symbol: Symbol,
}
struct Layout {
    slots: u64,
    temps: HashMap<Id, i64>,
    parallel: i64,
    output: i64,
    size: u64,
}
fn roots(path: &Path) -> Vec<Id> {
    let mut result = path.conditions.iter().map(|p| p.flags).collect::<Vec<_>>();
    for s in &path.stores {
        result.extend([s.address, s.value]);
    }
    result.extend(path.assignments.iter().map(|&(_, v)| v));
    if let End::Transfer {
        registers,
        flags,
        target,
    } = &path.end
    {
        result.extend(registers);
        result.extend([*flags, *target]);
    }
    result
}
fn collect(arena: &Expressions, id: Id, needed: &mut HashSet<Id>) {
    if !needed.insert(id) {
        return;
    }
    match *arena.node(id) {
        Expr::GuestPointer(a)
        | Expr::Extract(a, _, _)
        | Expr::Unary(_, a, _)
        | Expr::Load(a, _, _, _) => collect(arena, a, needed),
        Expr::Insert(a, b, _, _) | Expr::Binary(_, a, b, _) => {
            collect(arena, a, needed);
            collect(arena, b, needed);
        }
        Expr::Flags(_, a, b, c, _) | Expr::Divide(a, b, c, _, _, _) => {
            collect(arena, a, needed);
            collect(arena, b, needed);
            collect(arena, c, needed);
        }
        _ => {}
    }
}
fn temporary(arena: &Expressions, id: Id) -> bool {
    !matches!(
        arena.node(id),
        Expr::Constant(_)
            | Expr::Input(_)
            | Expr::Cell(_)
            | Expr::ImageBase
            | Expr::Function(_)
            | Expr::Continuation(_)
            | Expr::RuntimeData(_)
    )
}
impl Layout {
    fn new(graph: &Function<'_>) -> Result<Self> {
        let mut needed = HashSet::new();
        for b in graph.blocks {
            for p in &b.paths {
                for root in roots(p) {
                    collect(graph.arena, root, &mut needed);
                }
            }
        }
        let mut ids = needed
            .into_iter()
            .filter(|&id| temporary(graph.arena, id))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        let temps = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, ((graph.slots as usize + i) * 8) as i64))
            .collect();
        let parallel = ((graph.slots as usize + ids.len()) * 8) as i64;
        let copies = graph
            .blocks
            .iter()
            .flat_map(|b| &b.paths)
            .map(|p| p.assignments.len())
            .max()
            .unwrap_or(0);
        let output = parallel + (copies * 8) as i64;
        let size = (output as u64 + 152).div_ceil(16) * 16;
        ensure!(
            size <= 16 * 1024 * 1024,
            "native expression frame exceeds bounds"
        );
        Ok(Self {
            slots: graph.slots,
            temps,
            parallel,
            output,
            size,
        })
    }
}
struct Emitter<'a> {
    budget: &'a super::budget::Budget,
    asm: &'a mut CodeAssembler,
    arena: &'a Expressions,
    layout: &'a Layout,
    blocks: &'a [CodeLabel],
    fixups: &'a mut Vec<Fixup>,
    cache: HashSet<Id>,
}
impl Emitter<'_> {
    fn symbol(&mut self, symbol: Symbol) -> Result<()> {
        self.fixups.push(Fixup {
            instruction: self.asm.instructions().len(),
            symbol,
        });
        self.asm.mov(rax, 0x123456789abcdef0u64)?;
        Ok(())
    }
    fn value(&mut self, id: Id) -> Result<()> {
        self.expression(id)
            .with_context(|| format!("lower expression {id}: {:?}", self.arena.node(id)))?;
        match *self.arena.node(id) {
            Expr::Constant(v) => {
                ensure!(
                    !self.arena.private_address(v),
                    "native value retains a VM-private address {v:#x}"
                );
                self.asm.mov(rax, v)?;
            }
            Expr::Input(n) if n < 17 => self.asm.mov(rax, qword_ptr(rsi + (n * 8) as i64))?,
            Expr::Cell(n) => {
                ensure!(n < self.layout.slots, "native cell outside frame");
                self.asm.mov(rax, qword_ptr(rsi + (n * 8) as i64))?;
            }
            Expr::ImageBase => self.symbol(Symbol::Image(0))?,
            Expr::Function(rva) => self.symbol(Symbol::Image(rva))?,
            Expr::Continuation(at) => self.symbol(Symbol::Entry(Start::Continuation(at)))?,
            Expr::RuntimeData(at) => bail!("unlinked runtime data RVA {at:#x}"),
            Expr::Input(n) => bail!("native value depends on unresolved VM input {n:#x}"),
            _ => self.asm.mov(rax, qword_ptr(rsi + self.layout.temps[&id]))?,
        }
        Ok(())
    }
    fn pair(&mut self, a: Id, b: Id) -> Result<()> {
        self.expression(a)?;
        self.expression(b)?;
        self.value(b)?;
        self.asm.mov(rcx, rax)?;
        self.value(a)?;
        Ok(())
    }
    fn truncate(&mut self, width: u64) -> Result<()> {
        ensure!(
            matches!(width, 8 | 16 | 32 | 64),
            "unsupported native value width {width}"
        );
        if width == 32 {
            self.asm.mov(eax, eax)?;
        } else if width < 32 {
            self.asm.and(rax, ((1u64 << width) - 1) as i32)?;
        }
        Ok(())
    }
    fn binary(&mut self, op: M, width: u64, flags: bool) -> Result<()> {
        macro_rules! operation {
            ($method:ident) => {
                match width {
                    8 => self.asm.$method(al, cl)?,
                    16 => self.asm.$method(ax, cx)?,
                    32 => self.asm.$method(eax, ecx)?,
                    64 => self.asm.$method(rax, rcx)?,
                    _ => bail!("unsupported native ALU width {width}"),
                }
            };
        }
        match op {
            M::Add => operation!(add),
            M::Sub => operation!(sub),
            M::Cmp => {
                if flags {
                    operation!(cmp)
                } else {
                    operation!(sub)
                }
            }
            M::And => operation!(and),
            M::Test => {
                if flags {
                    operation!(test)
                } else {
                    operation!(and)
                }
            }
            M::Or => operation!(or),
            M::Xor => operation!(xor),
            M::Shl | M::Shr | M::Sar | M::Rol | M::Ror => {
                macro_rules! shift {
                    ($method:ident) => {
                        match width {
                            8 => self.asm.$method(al, cl)?,
                            16 => self.asm.$method(ax, cl)?,
                            32 => self.asm.$method(eax, cl)?,
                            64 => self.asm.$method(rax, cl)?,
                            _ => bail!("unsupported native shift width {width}"),
                        }
                    };
                }
                match op {
                    M::Shl => shift!(shl),
                    M::Shr => shift!(shr),
                    M::Sar => shift!(sar),
                    M::Rol => shift!(rol),
                    M::Ror => shift!(ror),
                    _ => bail!("unsupported native shift operation {op:?}"),
                }
            }
            M::Mul => {
                ensure!(flags, "unsupported native MUL value");
                match width {
                    32 => self.asm.mul(ecx)?,
                    64 => self.asm.mul(rcx)?,
                    _ => bail!("unsupported MUL width"),
                }
            }
            M::Imul => match width {
                8 if flags => self.asm.imul(cl)?,
                8 | 32 => self.asm.imul_2(eax, ecx)?,
                64 => self.asm.imul_2(rax, rcx)?,
                16 => self.asm.imul_2(ax, cx)?,
                _ => bail!("unsupported native IMUL width {width}"),
            },
            _ => bail!("unsupported native binary operation {op:?}"),
        }
        Ok(())
    }
    fn unary(&mut self, op: M, width: u64) -> Result<()> {
        macro_rules! operation {
            ($method:ident) => {
                match width {
                    8 => self.asm.$method(al)?,
                    16 => self.asm.$method(ax)?,
                    32 => self.asm.$method(eax)?,
                    64 => self.asm.$method(rax)?,
                    _ => bail!("unsupported native unary width {width}"),
                }
            };
        }
        match op {
            M::Not => operation!(not),
            M::Neg => operation!(neg),
            M::Inc => operation!(inc),
            M::Dec => operation!(dec),
            M::Bswap => match width {
                32 => self.asm.bswap(eax)?,
                64 => self.asm.bswap(rax)?,
                _ => bail!("unsupported narrow BSWAP"),
            },
            M::Movsx => match width {
                8 => self.asm.movsx(rax, al)?,
                16 => self.asm.movsx(rax, ax)?,
                32 => self.asm.movsxd(rax, eax)?,
                64 => {}
                _ => bail!("unsupported MOVSX width {width}"),
            },
            _ => bail!("unsupported native unary operation {op:?}"),
        }
        Ok(())
    }
    fn expression(&mut self, id: Id) -> Result<()> {
        if id.is_multiple_of(128) {
            self.budget.check(
                "x64 selection",
                format!(
                    "expression={id}, instructions={}",
                    self.asm.instructions().len()
                ),
            )?;
        }
        if !temporary(self.arena, id) || !self.cache.insert(id) {
            return Ok(());
        }
        match *self.arena.node(id) {
            Expr::PrivateAddress(at) => bail!("native value retains a VM-private address {at:#x}"),
            Expr::GuestPointer(a) => self.value(a)?,
            Expr::Extract(a, offset, width) => {
                ensure!(offset + width <= 64, "invalid bit extraction");
                self.value(a)?;
                if offset != 0 {
                    self.asm.shr(rax, offset as u32)?;
                }
                self.truncate(width)?;
            }
            Expr::Insert(a, b, offset, width) => {
                ensure!(offset + width <= 64, "invalid bit insertion");
                self.pair(a, b)?;
                let mask = if width == 64 {
                    u64::MAX
                } else {
                    ((1u64 << width) - 1) << offset
                };
                self.asm.mov(rdx, !mask)?;
                self.asm.and(rax, rdx)?;
                self.asm.shl(rcx, offset as u32)?;
                self.asm.mov(rdx, mask)?;
                self.asm.and(rcx, rdx)?;
                self.asm.or(rax, rcx)?;
            }
            Expr::Unary(op, a, width) => {
                self.value(a)?;
                self.unary(op, width)?;
                if op != M::Movsx {
                    self.truncate(width)?;
                }
            }
            Expr::Binary(op, a, b, width) => {
                self.pair(a, b)?;
                self.binary(op, width, false)?;
                self.truncate(width)?;
            }
            Expr::Divide(high, low, divisor, width, signed, remainder) => {
                self.expression(high)?;
                self.expression(low)?;
                self.expression(divisor)?;
                self.value(high)?;
                self.asm.mov(r8, rax)?;
                self.pair(low, divisor)?;
                self.asm.mov(rdx, r8)?;
                match (signed, width) {
                    (false, 16) => self.asm.div(cx)?,
                    (false, 32) => self.asm.div(ecx)?,
                    (false, 64) => self.asm.div(rcx)?,
                    (true, 16) => self.asm.idiv(cx)?,
                    (true, 32) => self.asm.idiv(ecx)?,
                    (true, 64) => self.asm.idiv(rcx)?,
                    _ => bail!("unsupported division width {width}"),
                }
                if remainder {
                    self.asm.mov(rax, rdx)?;
                }
                self.truncate(width)?;
            }
            Expr::Flags(op, a, b, old, width) => {
                self.expression(a)?;
                self.expression(b)?;
                self.value(old)?;
                self.asm.mov(rdx, rax)?;
                self.pair(a, b)?;
                self.asm.and(rdx, 0x8d5)?;
                self.asm.or(rdx, 2)?;
                self.asm.push(rdx)?;
                self.asm.popfq()?;
                if matches!(op, M::Inc | M::Dec | M::Neg) {
                    self.unary(op, width)?;
                } else {
                    self.binary(op, width, true)?;
                }
                self.asm.pushfq()?;
                self.asm.pop(rax)?;
                self.asm.and(
                    rax,
                    if matches!(op, M::Rol | M::Ror) {
                        0x801
                    } else {
                        0x8d5
                    },
                )?;
            }
            Expr::Load(address, width, segment, _) => {
                self.value(address)?;
                self.asm.mov(rdx, rax)?;
                let memory = qword_ptr(rdx);
                let memory = match segment {
                    R::FS => memory.fs(),
                    R::GS => memory.gs(),
                    _ => memory,
                };
                match width {
                    64 => self.asm.mov(rax, memory)?,
                    32 => {
                        let m = dword_ptr(rdx);
                        let m = match segment {
                            R::FS => m.fs(),
                            R::GS => m.gs(),
                            _ => m,
                        };
                        self.asm.mov(eax, m)?;
                    }
                    16 => {
                        let m = word_ptr(rdx);
                        let m = match segment {
                            R::FS => m.fs(),
                            R::GS => m.gs(),
                            _ => m,
                        };
                        self.asm.movzx(rax, m)?;
                    }
                    8 => {
                        let m = byte_ptr(rdx);
                        let m = match segment {
                            R::FS => m.fs(),
                            R::GS => m.gs(),
                            _ => m,
                        };
                        self.asm.movzx(rax, m)?;
                    }
                    _ => bail!("unsupported native load width {width}"),
                }
            }
            other => bail!("unexpected non-temporary expression {other:?}"),
        }
        self.asm.mov(qword_ptr(rsi + self.layout.temps[&id]), rax)?;
        Ok(())
    }
    fn pending_loads(&mut self, paths: &[&Path], epoch: u64) -> Result<()> {
        let mut needed = HashSet::new();
        for path in paths {
            for root in roots(path) {
                collect(self.arena, root, &mut needed);
            }
        }
        let mut loads = needed
            .into_iter()
            .filter(|&id| matches!(self.arena.node(id),Expr::Load(_,_,_,e)if *e<=epoch))
            .collect::<Vec<_>>();
        loads.sort_unstable();
        for load in loads {
            self.expression(load)?;
        }
        Ok(())
    }
    fn store(&mut self, store: &super::lift::Store) -> Result<()> {
        self.pair(store.value, store.address)?;
        self.asm.mov(rdx, rcx)?;
        match store.width {
            32 => {
                let m = dword_ptr(rdx);
                let m = match store.segment {
                    R::FS => m.fs(),
                    R::GS => m.gs(),
                    _ => m,
                };
                self.asm.mov(m, eax)?;
            }
            64 => {
                let m = qword_ptr(rdx);
                let m = match store.segment {
                    R::FS => m.fs(),
                    R::GS => m.gs(),
                    _ => m,
                };
                self.asm.mov(m, rax)?;
            }
            16 => {
                let m = word_ptr(rdx);
                let m = match store.segment {
                    R::FS => m.fs(),
                    R::GS => m.gs(),
                    _ => m,
                };
                self.asm.mov(m, ax)?;
            }
            8 => {
                let m = byte_ptr(rdx);
                let m = match store.segment {
                    R::FS => m.fs(),
                    R::GS => m.gs(),
                    _ => m,
                };
                self.asm.mov(m, al)?;
            }
            _ => bail!("unsupported native store width {}", store.width),
        }
        Ok(())
    }
    fn branch(&mut self, flags: Id, op: M, yes: CodeLabel) -> Result<()> {
        self.value(flags)?;
        self.asm.and(rax, 0x8d5)?;
        self.asm.or(rax, 2)?;
        self.asm.push(rax)?;
        self.asm.popfq()?;
        match op {
            M::Je => self.asm.je(yes)?,
            M::Jne => self.asm.jne(yes)?,
            M::Jb => self.asm.jb(yes)?,
            M::Jae => self.asm.jae(yes)?,
            M::Jbe => self.asm.jbe(yes)?,
            M::Ja => self.asm.ja(yes)?,
            M::Js => self.asm.js(yes)?,
            M::Jns => self.asm.jns(yes)?,
            M::Jo => self.asm.jo(yes)?,
            M::Jno => self.asm.jno(yes)?,
            M::Jp => self.asm.jp(yes)?,
            M::Jnp => self.asm.jnp(yes)?,
            M::Jl => self.asm.jl(yes)?,
            M::Jge => self.asm.jge(yes)?,
            M::Jle => self.asm.jle(yes)?,
            M::Jg => self.asm.jg(yes)?,
            _ => bail!("unsupported native condition {op:?}"),
        }
        Ok(())
    }
    fn paths(&mut self, paths: &[&Path], condition: usize, store: usize) -> Result<()> {
        ensure!(!paths.is_empty(), "empty native path group");
        let first = paths[0];
        let predicate = first.conditions.get(condition);
        let epoch = predicate.map_or(u64::MAX, |p| p.epoch);
        let mut done = store;
        while let Some(effect) = first.stores.get(done) {
            if effect.epoch >= epoch || !paths.iter().all(|p| p.stores.get(done) == Some(effect)) {
                break;
            }
            self.pending_loads(paths, effect.epoch)?;
            self.store(effect)?;
            done += 1;
        }
        if let Some(predicate) = predicate {
            ensure!(
                paths.iter().all(|p| p
                    .conditions
                    .get(condition)
                    .is_some_and(|c| c.flags == predicate.flags
                        && c.op == predicate.op
                        && c.epoch == predicate.epoch)),
                "native condition histories disagree"
            );
            let yes = paths
                .iter()
                .copied()
                .filter(|p| p.conditions[condition].taken)
                .collect::<Vec<_>>();
            let no = paths
                .iter()
                .copied()
                .filter(|p| !p.conditions[condition].taken)
                .collect::<Vec<_>>();
            ensure!(
                !yes.is_empty() && !no.is_empty(),
                "native CFG omits an unproved conditional successor"
            );
            let mut label = self.asm.create_label();
            self.branch(predicate.flags, predicate.op, label)?;
            let cache = self.cache.clone();
            self.paths(&no, condition + 1, done)?;
            self.cache = cache;
            self.asm.set_label(&mut label)?;
            self.paths(&yes, condition + 1, done)?;
            return Ok(());
        }
        ensure!(
            paths.len() == 1,
            "native paths overlap without a proved merge"
        );
        ensure!(
            done == first.stores.len(),
            "native memory effects lack a consistent order"
        );
        for (index, &(_, value)) in first.assignments.iter().enumerate() {
            self.value(value)?;
            self.asm.mov(
                qword_ptr(rsi + self.layout.parallel + (index * 8) as i64),
                rax,
            )?;
        }
        for (index, &(slot, _)) in first.assignments.iter().enumerate() {
            self.asm.mov(
                rax,
                qword_ptr(rsi + self.layout.parallel + (index * 8) as i64),
            )?;
            self.asm.mov(qword_ptr(rsi + (slot * 8) as i64), rax)?;
        }
        match &first.end {
            End::Next(block) => self.asm.jmp(self.blocks[*block])?,
            End::Transfer {
                registers,
                flags,
                target,
            } => {
                let output = self.layout.output;
                for (index, &value) in registers.iter().enumerate() {
                    self.value(value)?;
                    self.asm.mov(
                        qword_ptr(rsi + output + 16 + ((15 - index) * 8) as i64),
                        rax,
                    )?;
                }
                self.value(registers[4])?;
                self.asm.mov(qword_ptr(rsi + output), rax)?;
                self.value(*target)?;
                self.asm.mov(qword_ptr(rsi + output + 8), rax)?;
                self.value(*flags)?;
                self.asm.mov(qword_ptr(rsi + output + 144), rax)?;
                self.transfer()?;
            }
        }
        Ok(())
    }
    fn transfer(&mut self) -> Result<()> {
        let output = self.layout.output;
        self.asm.mov(rdx, qword_ptr(rsi + output))?;
        self.asm.sub(rdx, 144)?;
        self.asm.mov(rdi, rsi)?;
        self.asm.cmp(rdi, rdx)?;
        self.asm.cmova(rdi, rdx)?;
        self.asm.sub(rdi, 152)?;
        for i in 0..19 {
            self.asm.mov(rax, qword_ptr(rsi + output + i * 8))?;
            self.asm.mov(qword_ptr(rdi + i * 8), rax)?;
        }
        for i in 0..17 {
            self.asm.mov(rax, qword_ptr(rdi + 16 + i * 8))?;
            self.asm.mov(qword_ptr(rdx + i * 8), rax)?;
        }
        self.asm.mov(rax, qword_ptr(rdi + 8))?;
        self.asm.mov(qword_ptr(rdx + 136), rax)?;
        self.asm.mov(rsp, rdx)?;
        for register in [r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp] {
            self.asm.pop(register)?;
        }
        self.asm.add(rsp, 8)?; // Restore RSP after consuming the transfer record.
        for register in [rbx, rdx, rcx, rax] {
            self.asm.pop(register)?;
        }
        self.asm.popfq()?;
        self.asm.ret()?;
        Ok(())
    }
}
fn prologue(asm: &mut CodeAssembler, graph: &Function<'_>, layout: &Layout) -> Result<()> {
    asm.pushfq()?;
    for register in [
        rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ] {
        asm.push(register)?;
    }
    asm.sub(rsp, 16)?;
    asm.mov(rbp, rsp)?;
    let guest = graph.guest_stack.div_ceil(16) * 16 + 256;
    let frame = guest
        .checked_add(layout.size)
        .context("native stack extent overflow")?;
    let frame = i32::try_from(frame)?;
    asm.mov(rdx, rsp)?;
    asm.mov(rax, u64::try_from(frame + 256)?)?;
    let mut probe = asm.create_label();
    let mut tail = asm.create_label();
    asm.set_label(&mut probe)?;
    asm.cmp(rax, 4096)?;
    asm.jb(tail)?;
    asm.sub(rdx, 4096)?;
    asm.test(qword_ptr(rdx), rax)?;
    asm.sub(rax, 4096)?;
    asm.jmp(probe)?;
    asm.set_label(&mut tail)?;
    asm.sub(rdx, rax)?;
    asm.test(qword_ptr(rdx), rax)?;
    asm.sub(rsp, frame)?;
    asm.mov(rsi, rsp)?;
    for r in 0..16 {
        asm.mov(rax, qword_ptr(rbp + 16 + (15 - r) * 8))?;
        if r == 4 {
            asm.add(rax, 40)?;
        }
        asm.mov(qword_ptr(rsi + r * 8), rax)?;
        asm.mov(qword_ptr(rsi + (17 + r) * 8), rax)?;
    }
    asm.mov(rax, qword_ptr(rbp + 144))?;
    asm.mov(qword_ptr(rsi + 128), rax)?;
    asm.mov(qword_ptr(rsi + 264), rax)?;
    Ok(())
}
pub(crate) fn emit(
    graphs: &[Function<'_>],
    image_base: u64,
    rva: u64,
    budget: &super::budget::Budget,
) -> Result<Program> {
    ensure!(!graphs.is_empty(), "no native VM functions");
    let base = image_base.checked_add(rva).context("native VA overflow")?;
    let mut asm = CodeAssembler::new(64)?;
    let mut labels = HashMap::new();
    for g in graphs {
        ensure!(
            labels.insert(g.start, asm.create_label()).is_none(),
            "duplicate native start"
        );
    }
    let mut fixups = Vec::new();
    for graph in graphs {
        budget.check(
            "x64 frame planning",
            format!("{:?}, blocks={}", graph.start, graph.blocks.len()),
        )?;
        let layout = Layout::new(graph)?;
        asm.set_label(
            labels
                .get_mut(&graph.start)
                .context("missing native function label")?,
        )?;
        prologue(&mut asm, graph, &layout)?;
        let mut blocks = (0..graph.blocks.len())
            .map(|_| asm.create_label())
            .collect::<Vec<_>>();
        for block in 0..blocks.len() {
            if block.is_multiple_of(16) {
                budget.check("x64 selection", format!("{:?}, block={block}", graph.start))?;
            }
            asm.set_label(&mut blocks[block])?;
            let paths = graph.blocks[block].paths.iter().collect::<Vec<_>>();
            let mut emitter = Emitter {
                budget,
                asm: &mut asm,
                arena: graph.arena,
                layout: &layout,
                blocks: &blocks,
                fixups: &mut fixups,
                cache: HashSet::new(),
            };
            emitter
                .paths(&paths, 0, 0)
                .with_context(|| format!("emit {:?}, block {block}", graph.start))?;
        }
    }
    budget.check("x64 encoding", asm.instructions().len())?;
    let result = asm.assemble_options(base, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)?;
    let entries = labels
        .iter()
        .map(|(&start, label)| {
            Ok((
                start,
                result
                    .label_ip(label)?
                    .checked_sub(image_base)
                    .context("native label below image base")?,
            ))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    let offsets = &result.inner.new_instruction_offsets;
    let mut bytes = result.inner.code_buffer.clone();
    let mut relocations = Vec::new();
    for fixup in fixups {
        let offset = *offsets
            .get(fixup.instruction)
            .context("missing native instruction offset")?;
        ensure!(
            offset != u32::MAX,
            "native address instruction was rewritten"
        );
        let mut decoder = Decoder::with_ip(
            64,
            &bytes[offset as usize..],
            base + u64::from(offset),
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        let constant = decoder.get_constant_offsets(&instruction);
        ensure!(
            instruction.mnemonic() == M::Mov && constant.immediate_size() == 8,
            "native symbol is not an imm64 MOV"
        );
        let at = offset as usize + constant.immediate_offset();
        let value = match fixup.symbol {
            Symbol::Image(rva) => image_base
                .checked_add(rva)
                .context("image symbol overflow")?,
            Symbol::Entry(start) => image_base
                .checked_add(
                    *entries
                        .get(&start)
                        .context("uncompiled native continuation")?,
                )
                .context("native continuation overflow")?,
        };
        put_u64_at(&mut bytes, at, value)?;
        relocations.push(rva + at as u64);
    }
    budget.check("x64 verification", format!("bytes={}", bytes.len()))?;
    verify(&bytes, base)?;
    Ok(Program {
        bytes,
        entries,
        relocations,
    })
}
pub(crate) fn verify(bytes: &[u8], base: u64) -> Result<()> {
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut boundaries = HashSet::new();
    let mut branches = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        ensure!(!i.is_invalid(), "invalid emitted x64 at {:#x}", i.ip());
        boundaries.insert(i.ip());
        if matches!(
            i.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
        ) && matches!(i.op0_kind(), OpKind::NearBranch64)
        {
            branches.push((i.ip(), i.near_branch_target()));
        }
    }
    ensure!(
        decoder.position() == bytes.len(),
        "incomplete native x64 decode"
    );
    for (source, target) in branches {
        ensure!(
            boundaries.contains(&target),
            "native branch {source:#x} targets a non-instruction {target:#x}"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/devirt/x64/codegen.rs"]
mod tests;
