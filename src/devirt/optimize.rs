//! Propagate immutable values and executable edges before native lowering.
use super::{
    graph::{End, Graph, Path},
    ir::{Expr, Expressions, Id},
};
use anyhow::{Result, ensure};
use iced_x86::Mnemonic as M;
use std::collections::{HashMap, VecDeque};
type Facts = HashMap<u32, Id>;

fn rewrite(arena: &mut Expressions, id: Id, facts: &Facts, cache: &mut HashMap<Id, Id>) -> Id {
    if let Some(&value) = cache.get(&id) {
        return value;
    }
    let value = match *arena.node(id) {
        Expr::Cell(slot) => facts.get(&slot).copied().unwrap_or(id),
        Expr::GuestPointer(a) => {
            let a = rewrite(arena, a, facts, cache);
            arena.intern(Expr::GuestPointer(a))
        }
        Expr::Extract(a, at, w) => {
            let a = rewrite(arena, a, facts, cache);
            arena.extract(a, at, w)
        }
        Expr::Insert(a, b, at, w) => {
            let a = rewrite(arena, a, facts, cache);
            let b = rewrite(arena, b, facts, cache);
            arena.insert(a, b, at, w)
        }
        Expr::Unary(op, a, w) => {
            let a = rewrite(arena, a, facts, cache);
            arena.unary(op, a, w)
        }
        Expr::Binary(op, a, b, w) => {
            let a = rewrite(arena, a, facts, cache);
            let b = rewrite(arena, b, facts, cache);
            arena.binary(op, a, b, w)
        }
        Expr::Flags(op, a, b, c, w) => {
            let a = rewrite(arena, a, facts, cache);
            let b = rewrite(arena, b, facts, cache);
            let c = rewrite(arena, c, facts, cache);
            arena.intern(Expr::Flags(op, a, b, c, w))
        }
        Expr::Load(a, w, s, e) => {
            let a = rewrite(arena, a, facts, cache);
            arena.intern(Expr::Load(a, w, s, e))
        }
        _ => id,
    };
    cache.insert(id, value);
    value
}
fn immutable(arena: &Expressions, id: Id, cache: &mut HashMap<Id, bool>) -> bool {
    if let Some(&value) = cache.get(&id) {
        return value;
    }
    let value = match *arena.node(id) {
        Expr::Cell(_) | Expr::Load(..) => false,
        Expr::GuestPointer(a) | Expr::Extract(a, _, _) | Expr::Unary(_, a, _) => {
            immutable(arena, a, cache)
        }
        Expr::Insert(a, b, _, _) | Expr::Binary(_, a, b, _) => {
            immutable(arena, a, cache) && immutable(arena, b, cache)
        }
        Expr::Flags(_, a, b, c, _) => {
            immutable(arena, a, cache) && immutable(arena, b, cache) && immutable(arena, c, cache)
        }
        _ => true,
    };
    cache.insert(id, value);
    value
}
fn rewrite_path(arena: &mut Expressions, original: &Path, facts: &Facts) -> Option<(Path, Facts)> {
    let mut path = original.clone();
    let mut cache = HashMap::new();
    let mut conditions = Vec::new();
    for mut condition in path.conditions {
        condition.flags = rewrite(arena, condition.flags, facts, &mut cache);
        let mask = arena.constant(super::ir::condition_mask(condition.op));
        condition.flags = arena.binary(M::And, condition.flags, mask, 32);
        if let Some(taken) = arena.condition(condition.flags, condition.op) {
            if taken != condition.taken {
                return None;
            }
        } else {
            conditions.push(condition);
        }
    }
    path.conditions = conditions;
    for s in &mut path.stores {
        s.address = rewrite(arena, s.address, facts, &mut cache);
        s.value = rewrite(arena, s.value, facts, &mut cache);
    }
    for (_, value) in &mut path.assignments {
        *value = rewrite(arena, *value, facts, &mut cache);
    }
    path.assignments
        .retain(|(slot, value)| facts.get(slot) != Some(value));
    if let End::Transfer {
        registers,
        flags,
        target,
    } = &mut path.end
    {
        for v in registers {
            *v = rewrite(arena, *v, facts, &mut cache);
        }
        *flags = rewrite(arena, *flags, facts, &mut cache);
        *target = rewrite(arena, *target, facts, &mut cache);
    }
    let mut outgoing = facts.clone();
    let mut memo = HashMap::new();
    // Every RHS sees the same incoming state; register copies are parallel.
    for &(slot, value) in &path.assignments {
        if immutable(arena, value, &mut memo) {
            outgoing.insert(slot, value);
        } else {
            outgoing.remove(&slot);
        }
    }
    Some((path, outgoing))
}
pub(crate) fn run(graph: &mut Graph) -> Result<()> {
    for round in 0..64 {
        graph.session.budget.check(
            "semantic fixed point",
            format!("{:?}, round={round}", graph.start),
        )?;
        let before = graph.blocks.clone();
        optimize_round(graph)?;
        if graph.blocks == before {
            return Ok(());
        }
    }
    anyhow::bail!(
        "native semantic optimization did not converge for {:?}",
        graph.start
    )
}

fn optimize_round(graph: &mut Graph) -> Result<()> {
    let mut incoming: Vec<Option<Facts>> = vec![None; graph.blocks.len()];
    let mut initial = Facts::new();
    for r in 0..8 {
        initial.insert(9 + r, graph.session.expressions.input(r));
    }
    initial.insert(17, graph.session.expressions.input(8));
    incoming[0] = Some(initial);
    let mut pending = VecDeque::from([0usize]);
    let mut iterations = 0usize;
    while let Some(block) = pending.pop_front() {
        iterations += 1;
        if iterations.is_multiple_of(32) {
            graph.session.budget.check(
                "SSA propagation",
                format!(
                    "{:?}, block={block}, iterations={iterations}, pending={}, expressions={}",
                    graph.start,
                    pending.len(),
                    graph.session.expressions.len()
                ),
            )?;
        }
        ensure!(
            iterations <= 300000,
            "native semantic propagation exceeds bounds"
        );
        let facts = incoming[block].as_ref().unwrap().clone();
        for original in &graph.blocks[block].paths {
            let Some((path, outgoing)) =
                rewrite_path(&mut graph.session.expressions, original, &facts)
            else {
                continue;
            };
            let End::Next(next) = path.end else {
                continue;
            };
            let changed = if let Some(previous) = &mut incoming[next] {
                let before = previous.len();
                previous.retain(|slot, value| outgoing.get(slot) == Some(value));
                before != previous.len()
            } else {
                incoming[next] = Some(outgoing);
                true
            };
            if changed {
                pending.push_back(next);
            }
        }
    }
    for (block, facts) in incoming.iter().enumerate() {
        if block.is_multiple_of(32) {
            graph
                .session
                .budget
                .check("SSA rewrite", format!("{:?}, block={block}", graph.start))?;
        }
        graph.blocks[block].paths = if let Some(facts) = facts {
            graph.blocks[block]
                .paths
                .iter()
                .filter_map(|p| {
                    rewrite_path(&mut graph.session.expressions, p, facts).map(|(p, _)| p)
                })
                .collect()
        } else {
            Vec::new()
        };
    }
    for _ in 0..graph.blocks.len() {
        graph.session.budget.check(
            "empty block elimination",
            format!("{:?}, blocks={}", graph.start, graph.blocks.len()),
        )?;
        graph.simplify()?;
        let mut redirect = (0..graph.blocks.len()).collect::<Vec<_>>();
        for (index, target) in redirect.iter_mut().enumerate() {
            let mut seen = std::collections::HashSet::new();
            let mut cursor = index;
            while seen.insert(cursor) {
                let block = &graph.blocks[cursor];
                let [path] = block.paths.as_slice() else {
                    break;
                };
                if !path.conditions.is_empty()
                    || !path.stores.is_empty()
                    || !path.assignments.is_empty()
                {
                    break;
                }
                let End::Next(next) = path.end else {
                    break;
                };
                cursor = next;
            }
            if seen.contains(&cursor) && cursor != index {
                let b = &graph.blocks[cursor];
                if let [p] = b.paths.as_slice()
                    && p.conditions.is_empty()
                    && p.stores.is_empty()
                    && p.assignments.is_empty()
                    && matches!(p.end, End::Next(_))
                {
                    continue;
                }
            }
            *target = cursor;
        }
        let mut changed = false;
        for b in &mut graph.blocks {
            for p in &mut b.paths {
                if let End::Next(n) = &mut p.end {
                    let target = redirect[*n];
                    changed |= target != *n;
                    *n = target;
                }
            }
        }
        if !changed {
            break;
        }
    }
    graph.simplify()?;
    let mut live = vec![false; graph.blocks.len()];
    let mut pending = vec![0];
    while let Some(b) = pending.pop() {
        if std::mem::replace(&mut live[b], true) {
            continue;
        }
        ensure!(
            !graph.blocks[b].paths.is_empty(),
            "native CFG reaches an unresolved frontier at block {b}"
        );
        for p in &graph.blocks[b].paths {
            if let End::Next(n) = p.end {
                pending.push(n);
            }
        }
    }
    let mut map = vec![0usize; live.len()];
    let mut count = 0;
    for (i, &keep) in live.iter().enumerate() {
        if keep {
            map[i] = count;
            count += 1;
        }
    }
    let mut i = 0;
    graph.blocks.retain(|_| {
        let keep = live[i];
        i += 1;
        keep
    });
    for b in &mut graph.blocks {
        for p in &mut b.paths {
            if let End::Next(n) = &mut p.end {
                *n = map[*n];
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../test/semantic_cfg.rs"]
mod tests;
