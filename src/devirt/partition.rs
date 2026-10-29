//! Refine CFG equivalence classes using predecessor splitters.
use super::{
    budget::Budget,
    graph::{Block, End, Path},
};
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};

pub(super) fn classes(blocks: &[Block], budget: &Budget) -> Result<Vec<usize>> {
    let mut labels = HashMap::<Vec<Path>, usize>::new();
    let mut groups = Vec::<HashSet<usize>>::new();
    let mut class = Vec::with_capacity(blocks.len());
    let mut incoming = vec![Vec::new(); blocks.len()];
    for (source, block) in blocks.iter().enumerate() {
        let mut label = block.paths.clone();
        for (edge, path) in label.iter_mut().enumerate() {
            if let End::Next(target) = &mut path.end {
                incoming[*target].push((source, edge));
                *target = 0;
            }
        }
        let count = labels.len();
        let id = *labels.entry(label).or_insert(count);
        if id == groups.len() {
            groups.push(HashSet::new());
        }
        groups[id].insert(source);
        class.push(id);
    }
    let mut queue = (0..groups.len()).collect::<VecDeque<_>>();
    let mut iterations = 0usize;
    while let Some(splitter) = queue.pop_front() {
        iterations += 1;
        if iterations.is_multiple_of(128) {
            budget.check(
                "CFG partition",
                format!(
                    "blocks={}, classes={}, splitters={iterations}",
                    blocks.len(),
                    groups.len()
                ),
            )?;
        }
        // Path position is a transition label: the initial partition already
        // distinguishes conditions, stores, assignments and terminal outputs.
        let mut by_edge = HashMap::<usize, Vec<usize>>::new();
        for &target in &groups[splitter] {
            for &(source, edge) in &incoming[target] {
                by_edge.entry(edge).or_default().push(source);
            }
        }
        let mut edges = by_edge.into_iter().collect::<Vec<_>>();
        edges.sort_unstable_by_key(|(edge, _)| *edge);
        for (_, sources) in edges {
            let mut affected = HashMap::<usize, Vec<usize>>::new();
            for source in sources {
                affected.entry(class[source]).or_default().push(source);
            }
            let mut affected = affected.into_iter().collect::<Vec<_>>();
            affected.sort_unstable_by_key(|(id, _)| *id);
            for (old, sources) in affected {
                if sources.len() == groups[old].len() {
                    continue;
                }
                let mut moved = sources.into_iter().collect::<HashSet<_>>();
                // Only members of the smaller side change their class number.
                if moved.len() > groups[old].len() / 2 {
                    moved = groups[old].difference(&moved).copied().collect();
                }
                let new = groups.len();
                for &source in &moved {
                    groups[old].remove(&source);
                    class[source] = new;
                }
                groups.push(moved);
                queue.push_back(new);
                // If `old` is queued it will process the other side as well.
                // Otherwise its preimage was already split, so the smaller
                // new side suffices (each edge is revisited O(log n) times).
            }
        }
    }
    Ok(class)
}
