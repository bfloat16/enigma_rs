//! Direct i386 instruction selection and encoding. No external compiler.
use super::{
    graph::{End, Graph, Path, Start},
    ir::{Expr, Expressions, Id},
};
use crate::common::io::put_u32_at;
use anyhow::{Context, Result, bail, ensure};
use iced_x86::{
    BlockEncoderOptions, Decoder, DecoderOptions, FlowControl, Mnemonic as M, OpKind,
    Register as R, code_asm::*,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub(crate) struct Program {
    pub bytes: Vec<u8>,
    pub entries: HashMap<Start, u32>,
    pub relocations: Vec<u32>,
}
pub(crate) struct Function<'a> {
    pub arena: &'a Expressions,
    pub blocks: &'a [super::graph::Block],
    pub slots: u32,
    pub start: Start,
    pub guest_stack: u32,
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
#[derive(Clone, Copy)]
enum Symbol {
    Image(u32),
    Entry(Start),
}
struct Fixup {
    instruction: usize,
    symbol: Symbol,
}
struct Layout {
    slots: u32,
    temps: HashMap<Id, i32>,
    parallel: i32,
    output: i32,
    size: u32,
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
        Expr::Flags(_, a, b, c, _) => {
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
            | Expr::Bytecode(_)
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
            .map(|(i, &id)| (id, ((graph.slots as usize + i) * 4) as i32))
            .collect();
        let parallel = ((graph.slots as usize + ids.len()) * 4) as i32;
        let copies = graph
            .blocks
            .iter()
            .flat_map(|b| &b.paths)
            .map(|p| p.assignments.len())
            .max()
            .unwrap_or(0);
        let output = parallel + (copies * 4) as i32;
        let size = (output as u32 + 44).div_ceil(16) * 16;
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
        self.asm.mov(eax, 0x12345678u32)?;
        Ok(())
    }
    fn value(&mut self, id: Id) -> Result<()> {
        self.expression(id)
            .with_context(|| format!("lower expression {id}: {:?}", self.arena.node(id)))?;
        match *self.arena.node(id) {
            Expr::Constant(v) => self.asm.mov(eax, v)?,
            Expr::Input(n) if n < 9 => self.asm.mov(eax, dword_ptr(esi + (n * 4) as i32))?,
            Expr::Cell(n) => {
                ensure!(n < self.layout.slots, "native cell outside frame");
                self.asm.mov(eax, dword_ptr(esi + (n * 4) as i32))?;
            }
            Expr::ImageBase => self.symbol(Symbol::Image(0))?,
            Expr::Function(rva) => self.symbol(Symbol::Image(rva))?,
            Expr::Continuation(at) => self.symbol(Symbol::Entry(Start::Continuation(at)))?,
            Expr::Bytecode(at) => self.symbol(Symbol::Entry(Start::Code(at)))?,
            Expr::Input(n) => bail!("native value depends on unresolved VM input {n:#x}"),
            _ => self.asm.mov(eax, dword_ptr(esi + self.layout.temps[&id]))?,
        }
        Ok(())
    }
    fn pair(&mut self, a: Id, b: Id) -> Result<()> {
        self.expression(a)?;
        self.expression(b)?;
        self.value(b)?;
        self.asm.mov(ecx, eax)?;
        self.value(a)?;
        Ok(())
    }
    fn truncate(&mut self, width: u32) -> Result<()> {
        ensure!(
            matches!(width, 8 | 16 | 32),
            "unsupported native value width {width}"
        );
        if width < 32 {
            self.asm.and(eax, ((1u32 << width) - 1) as i32)?;
        }
        Ok(())
    }
    fn binary(&mut self, op: M, width: u32, flags: bool) -> Result<()> {
        macro_rules! operation {
            ($method:ident) => {
                match width {
                    8 => self.asm.$method(al, cl)?,
                    16 => self.asm.$method(ax, cx)?,
                    32 => self.asm.$method(eax, ecx)?,
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
                    _ => unreachable!(),
                }
            }
            M::Mul => {
                ensure!(width == 32 && flags, "unsupported native MUL operation");
                self.asm.mul(ecx)?;
            }
            M::Imul => match width {
                8 if flags => self.asm.imul(cl)?,
                8 | 32 => self.asm.imul_2(eax, ecx)?,
                16 => self.asm.imul_2(ax, cx)?,
                _ => bail!("unsupported native IMUL width {width}"),
            },
            _ => bail!("unsupported native binary operation {op:?}"),
        }
        Ok(())
    }
    fn unary(&mut self, op: M, width: u32) -> Result<()> {
        macro_rules! operation {
            ($method:ident) => {
                match width {
                    8 => self.asm.$method(al)?,
                    16 => self.asm.$method(ax)?,
                    32 => self.asm.$method(eax)?,
                    _ => bail!("unsupported native unary width {width}"),
                }
            };
        }
        match op {
            M::Not => operation!(not),
            M::Neg => operation!(neg),
            M::Inc => operation!(inc),
            M::Dec => operation!(dec),
            M::Bswap => {
                ensure!(width == 32, "unsupported narrow BSWAP");
                self.asm.bswap(eax)?;
            }
            M::Movsx => match width {
                8 => self.asm.movsx(eax, al)?,
                16 => self.asm.movsx(eax, ax)?,
                32 => {}
                _ => bail!("unsupported MOVSX width {width}"),
            },
            _ => bail!("unsupported native unary operation {op:?}"),
        }
        Ok(())
    }
    fn expression(&mut self, id: Id) -> Result<()> {
        if id.is_multiple_of(128) {
            self.budget.check(
                "x86 selection",
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
                ensure!(offset + width <= 32, "invalid bit extraction");
                self.value(a)?;
                if offset != 0 {
                    self.asm.shr(eax, offset)?;
                }
                self.truncate(width)?;
            }
            Expr::Insert(a, b, offset, width) => {
                ensure!(offset + width <= 32, "invalid bit insertion");
                self.pair(a, b)?;
                let mask = if width == 32 {
                    u32::MAX
                } else {
                    ((1u32 << width) - 1) << offset
                };
                self.asm.and(eax, !mask as i32)?;
                self.asm.shl(ecx, offset)?;
                self.asm.and(ecx, mask as i32)?;
                self.asm.or(eax, ecx)?;
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
            Expr::Flags(op, a, b, old, width) => {
                self.expression(a)?;
                self.expression(b)?;
                self.value(old)?;
                self.asm.mov(edx, eax)?;
                self.pair(a, b)?;
                self.asm.and(edx, 0x8d5)?;
                self.asm.or(edx, 2)?;
                self.asm.push(edx)?;
                self.asm.popfd()?;
                if matches!(op, M::Inc | M::Dec | M::Neg) {
                    self.unary(op, width)?;
                } else {
                    self.binary(op, width, true)?;
                }
                self.asm.pushfd()?;
                self.asm.pop(eax)?;
                self.asm.and(
                    eax,
                    if matches!(op, M::Rol | M::Ror) {
                        0x801
                    } else {
                        0x8d5
                    },
                )?;
            }
            Expr::Load(address, width, segment, _) => {
                self.value(address)?;
                self.asm.mov(edx, eax)?;
                let memory = dword_ptr(edx);
                let memory = match segment {
                    R::FS => memory.fs(),
                    R::GS => memory.gs(),
                    _ => memory,
                };
                match width {
                    32 => self.asm.mov(eax, memory)?,
                    16 => {
                        let m = word_ptr(edx);
                        let m = match segment {
                            R::FS => m.fs(),
                            R::GS => m.gs(),
                            _ => m,
                        };
                        self.asm.movzx(eax, m)?;
                    }
                    8 => {
                        let m = byte_ptr(edx);
                        let m = match segment {
                            R::FS => m.fs(),
                            R::GS => m.gs(),
                            _ => m,
                        };
                        self.asm.movzx(eax, m)?;
                    }
                    _ => bail!("unsupported native load width {width}"),
                }
            }
            _ => unreachable!(),
        }
        self.asm.mov(dword_ptr(esi + self.layout.temps[&id]), eax)?;
        Ok(())
    }
    fn pending_loads(&mut self, paths: &[&Path], epoch: u32) -> Result<()> {
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
        self.asm.mov(edx, ecx)?;
        match store.width {
            32 => {
                let m = dword_ptr(edx);
                let m = match store.segment {
                    R::FS => m.fs(),
                    R::GS => m.gs(),
                    _ => m,
                };
                self.asm.mov(m, eax)?;
            }
            16 => {
                let m = word_ptr(edx);
                let m = match store.segment {
                    R::FS => m.fs(),
                    R::GS => m.gs(),
                    _ => m,
                };
                self.asm.mov(m, ax)?;
            }
            8 => {
                let m = byte_ptr(edx);
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
        self.asm.and(eax, 0x8d5)?;
        self.asm.or(eax, 2)?;
        self.asm.push(eax)?;
        self.asm.popfd()?;
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
        let epoch = predicate.map_or(u32::MAX, |p| p.epoch);
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
                dword_ptr(esi + self.layout.parallel + (index * 4) as i32),
                eax,
            )?;
        }
        for (index, &(slot, _)) in first.assignments.iter().enumerate() {
            self.asm.mov(
                eax,
                dword_ptr(esi + self.layout.parallel + (index * 4) as i32),
            )?;
            self.asm.mov(dword_ptr(esi + (slot * 4) as i32), eax)?;
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
                    self.asm
                        .mov(dword_ptr(esi + output + 8 + ((7 - index) * 4) as i32), eax)?;
                }
                self.value(registers[4])?;
                self.asm.mov(dword_ptr(esi + output), eax)?;
                self.value(*target)?;
                self.asm.mov(dword_ptr(esi + output + 4), eax)?;
                self.value(*flags)?;
                self.asm.mov(dword_ptr(esi + output + 40), eax)?;
                self.transfer()?;
            }
        }
        Ok(())
    }
    fn transfer(&mut self) -> Result<()> {
        let output = self.layout.output;
        self.asm.mov(edx, dword_ptr(esi + output))?;
        self.asm.sub(edx, 40)?;
        // Copy to scratch below both the compiler frame and target stack. This
        // also handles a dynamic ESP whose target overlaps the transfer record.
        self.asm.mov(edi, esi)?;
        self.asm.cmp(edi, edx)?;
        self.asm.cmova(edi, edx)?;
        self.asm.sub(edi, 44)?;
        for i in 0..11 {
            self.asm.mov(eax, dword_ptr(esi + output + i * 4))?;
            self.asm.mov(dword_ptr(edi + i * 4), eax)?;
        }
        for i in 0..9 {
            self.asm.mov(eax, dword_ptr(edi + 8 + i * 4))?;
            self.asm.mov(dword_ptr(edx + i * 4), eax)?;
        }
        self.asm.mov(eax, dword_ptr(edi + 4))?;
        self.asm.mov(dword_ptr(edx + 36), eax)?;
        self.asm.mov(esp, edx)?;
        self.asm.popad()?;
        self.asm.popfd()?;
        self.asm.ret()?;
        Ok(())
    }
}
fn prologue(asm: &mut CodeAssembler, graph: &Function<'_>, layout: &Layout) -> Result<()> {
    asm.pushfd()?;
    asm.pushad()?;
    asm.sub(esp, 8)?;
    asm.mov(ebp, esp)?;
    let guest = graph.guest_stack.div_ceil(16) * 16 + 64;
    let frame = guest
        .checked_add(layout.size)
        .context("native stack extent overflow")?;
    asm.mov(edx, esp)?;
    asm.mov(
        eax,
        frame
            .checked_add(64)
            .context("native scratch probe overflow")?,
    )?;
    let mut probe = asm.create_label();
    let mut tail = asm.create_label();
    asm.set_label(&mut probe)?;
    asm.cmp(eax, 4096)?;
    asm.jb(tail)?;
    asm.sub(edx, 4096)?;
    asm.test(dword_ptr(edx), eax)?;
    asm.sub(eax, 4096)?;
    asm.jmp(probe)?;
    asm.set_label(&mut tail)?;
    asm.sub(edx, eax)?;
    asm.test(dword_ptr(edx), eax)?;
    asm.sub(esp, frame)?;
    asm.mov(esi, esp)?;
    for r in 0..8 {
        asm.mov(eax, dword_ptr(ebp + 8 + (7 - r) * 4))?;
        if r == 4 {
            asm.add(eax, 4)?;
        }
        asm.mov(dword_ptr(esi + r * 4), eax)?;
        asm.mov(dword_ptr(esi + (9 + r) * 4), eax)?;
    }
    asm.mov(eax, dword_ptr(ebp + 40))?;
    asm.mov(dword_ptr(esi + 32), eax)?;
    asm.mov(dword_ptr(esi + 68), eax)?;
    Ok(())
}
#[cfg(test)]
pub(crate) fn emit(graphs: &[Function<'_>], image_base: u32, rva: u32) -> Result<Program> {
    emit_with_budget(graphs, image_base, rva, &super::budget::Budget::new()?)
}

pub(crate) fn emit_with_budget(
    graphs: &[Function<'_>],
    image_base: u32,
    rva: u32,
    budget: &super::budget::Budget,
) -> Result<Program> {
    ensure!(!graphs.is_empty(), "no native VM functions");
    let base = image_base.checked_add(rva).context("native VA overflow")?;
    let mut asm = CodeAssembler::new(32)?;
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
            "x86 frame planning",
            format!("{:?}, blocks={}", graph.start, graph.blocks.len()),
        )?;
        let layout = Layout::new(graph)?;
        asm.set_label(labels.get_mut(&graph.start).unwrap())?;
        prologue(&mut asm, graph, &layout)?;
        let mut blocks = (0..graph.blocks.len())
            .map(|_| asm.create_label())
            .collect::<Vec<_>>();
        for block in 0..blocks.len() {
            if block.is_multiple_of(16) {
                budget.check("x86 selection", format!("{:?}, block={block}", graph.start))?;
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
    budget.check("x86 encoding", asm.instructions().len())?;
    let result = asm.assemble_options(
        u64::from(base),
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
    )?;
    let entries = labels
        .iter()
        .map(|(&start, label)| {
            Ok((
                start,
                u32::try_from(result.label_ip(label)?)?
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
            32,
            &bytes[offset as usize..],
            u64::from(base + offset),
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        let constant = decoder.get_constant_offsets(&instruction);
        ensure!(
            instruction.mnemonic() == M::Mov && constant.immediate_size() == 4,
            "native symbol is not an imm32 MOV"
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
        put_u32_at(&mut bytes, at, value)?;
        relocations.push(rva + at as u32);
    }
    budget.check("x86 verification", format!("bytes={}", bytes.len()))?;
    verify(&bytes, base)?;
    Ok(Program {
        bytes,
        entries,
        relocations,
    })
}
pub(crate) fn verify(bytes: &[u8], base: u32) -> Result<()> {
    let mut decoder = Decoder::with_ip(32, bytes, u64::from(base), DecoderOptions::NONE);
    let mut boundaries = HashSet::new();
    let mut branches = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        ensure!(!i.is_invalid(), "invalid emitted x86 at {:#x}", i.ip());
        boundaries.insert(i.ip());
        if matches!(
            i.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
        ) && matches!(i.op0_kind(), OpKind::NearBranch32 | OpKind::NearBranch16)
        {
            branches.push((i.ip(), i.near_branch_target()));
        }
    }
    ensure!(
        decoder.position() == bytes.len(),
        "incomplete native x86 decode"
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
#[path = "../../test/native_codegen.rs"]
mod tests;
