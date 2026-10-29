//! Backward bit liveness for parallel edge assignments. In particular, flags
//! overwritten by a later handler must not keep callback-clobbered bits alive.
use super::{
    graph::{End, Graph, Path},
    ir::{Expr, Expressions, Id, condition_mask},
};
use anyhow::Result;
use iced_x86::Mnemonic as M;
use std::collections::{HashMap, HashSet, VecDeque};

type Bits = HashMap<u32, u32>;
fn mask(width: u32) -> u32 {
    u32::MAX >> (32 - width)
}
fn merge(into: &mut Bits, from: &Bits) {
    for (&slot, &bits) in from {
        *into.entry(slot).or_default() |= bits;
    }
}

fn need(arena: &Expressions, id: Id, bits: u32, cells: &mut Bits, seen: &mut Bits) {
    let previous = seen.entry(id).or_default();
    let bits = bits & !*previous;
    if bits == 0 {
        return;
    }
    *previous |= bits;
    let mut child = |id, bits| need(arena, id, bits, cells, seen);
    match *arena.node(id) {
        Expr::Cell(slot) => {
            *cells.entry(slot).or_default() |= bits;
        }
        Expr::GuestPointer(a) => child(a, bits),
        Expr::Extract(a, at, width) => child(a, (bits & mask(width)) << at),
        Expr::Insert(a, b, at, width) => {
            let written = mask(width) << at;
            child(a, bits & !written);
            child(b, (bits & written) >> at);
        }
        Expr::Unary(M::Not, a, width) => child(a, bits & mask(width)),
        Expr::Unary(M::Bswap, a, _) => child(a, bits.swap_bytes()),
        Expr::Unary(_, a, width) => child(a, mask(width)),
        Expr::Binary(op, a, b, width) => {
            let bits = bits & mask(width);
            match op {
                M::And | M::Test => {
                    child(a, bits & arena.value(b).unwrap_or(u32::MAX));
                    child(b, bits & arena.value(a).unwrap_or(u32::MAX));
                }
                M::Or => {
                    child(a, bits & !arena.value(b).unwrap_or(0));
                    child(b, bits & !arena.value(a).unwrap_or(0));
                }
                M::Xor => {
                    child(a, bits);
                    child(b, bits);
                }
                M::Add | M::Sub | M::Imul if bits != 0 => {
                    let low = u32::MAX >> bits.leading_zeros();
                    child(a, low);
                    child(b, low);
                }
                _ => {
                    child(a, mask(width));
                    child(b, mask(width));
                }
            }
        }
        Expr::Flags(_, a, b, old, width) => {
            child(a, mask(width));
            child(b, mask(width));
            child(old, bits);
        }
        Expr::Load(a, _, _, _) => child(a, u32::MAX),
        _ => {}
    }
}

fn outgoing(arena: &Expressions, path: &Path, live: &[Bits]) -> Bits {
    match &path.end {
        End::Next(next) => live[*next].clone(),
        End::Transfer {
            registers,
            flags,
            target,
        } => {
            let mut cells = Bits::new();
            let mut seen = Bits::new();
            for &id in registers.iter().chain([flags, target]) {
                need(arena, id, u32::MAX, &mut cells, &mut seen);
            }
            cells
        }
    }
}

pub(super) fn prune(graph: &mut Graph) -> Result<()> {
    let arena = &graph.session.expressions;
    let mut predecessors = vec![Vec::new(); graph.blocks.len()];
    for (block, data) in graph.blocks.iter().enumerate() {
        for path in &data.paths {
            if let End::Next(next) = path.end {
                predecessors[next].push(block);
            }
        }
    }
    let mut live = vec![Bits::new(); graph.blocks.len()];
    let mut queue = (0..graph.blocks.len()).rev().collect::<VecDeque<_>>();
    let mut queued = vec![true; graph.blocks.len()];
    let mut updates = 0usize;
    while let Some(block) = queue.pop_front() {
        queued[block] = false;
        updates += 1;
        if updates.is_multiple_of(128) {
            graph.session.budget.check(
                "bit liveness",
                format!("{:?}, block={block}, updates={updates}", graph.start),
            )?;
        }
        let mut incoming = Bits::new();
        let mut seen = Bits::new();
        for path in &graph.blocks[block].paths {
            let out = outgoing(arena, path, &live);
            let assigned = path.assignments.iter().map(|p| p.0).collect::<HashSet<_>>();
            for (&slot, &bits) in &out {
                if !assigned.contains(&slot) {
                    *incoming.entry(slot).or_default() |= bits;
                }
            }
            for &(slot, value) in &path.assignments {
                need(
                    arena,
                    value,
                    out.get(&slot).copied().unwrap_or(0),
                    &mut incoming,
                    &mut seen,
                );
            }
            for p in &path.conditions {
                need(
                    arena,
                    p.flags,
                    condition_mask(p.op),
                    &mut incoming,
                    &mut seen,
                );
            }
            for s in &path.stores {
                need(arena, s.address, u32::MAX, &mut incoming, &mut seen);
                need(arena, s.value, mask(s.width), &mut incoming, &mut seen);
            }
        }
        let old = live[block].clone();
        merge(&mut live[block], &incoming);
        if old != live[block] {
            for &pred in &predecessors[block] {
                if !queued[pred] {
                    queue.push_back(pred);
                    queued[pred] = true;
                }
            }
        }
    }
    let arena = &mut graph.session.expressions;
    for block in &mut graph.blocks {
        for path in &mut block.paths {
            let needed = outgoing(arena, path, &live);
            path.assignments.retain_mut(|(slot, value)| {
                let bits = needed.get(slot).copied().unwrap_or(0);
                if bits == 0 {
                    return false;
                }
                if bits != u32::MAX {
                    let mask = arena.constant(bits);
                    *value = arena.binary(M::And, *value, mask, 32);
                }
                // Compare on live bits only. Masking dead flag bits must not
                // turn a no-op into an observable edge assignment: that would
                // prevent equivalent opaque branches from ever merging.
                let old = arena.intern(Expr::Cell(*slot));
                let mask = arena.constant(bits);
                let old = arena.binary(M::And, old, mask, 32);
                *value != old
            });
        }
    }
    Ok(())
}
