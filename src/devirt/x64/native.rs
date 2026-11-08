//! Recover and link x64 VM functions and their native continuations.
use super::{
    codegen,
    graph::{Graph, Start},
    profile::Profile,
    switch::Session,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

pub(super) fn compile(
    loader: &[u8],
    header: Option<&[u8]>,
    profile: Arc<Profile>,
    roots: &[u64],
    entry: u64,
    image_base: u64,
    rva: u64,
) -> Result<codegen::Program> {
    let budget = super::budget::Budget::new()?;
    let mut pending = roots
        .iter()
        .copied()
        .map(Start::Function)
        .collect::<VecDeque<_>>();
    let mut visited = HashSet::new();
    let mut graphs = Vec::new();
    while let Some(start) = pending.pop_front() {
        if !visited.insert(start) {
            continue;
        }
        ensure!(graphs.len() < 4096, "native VM continuations exceed bounds");
        budget.check(
            "function queue",
            format!(
                "{start:?}, completed={}, pending={}",
                graphs.len(),
                pending.len()
            ),
        )?;
        let mut session =
            Session::from_start(loader, profile.clone(), start, entry, budget.clone())
                .with_context(|| format!("initialize VM analysis for {start:?}"))?;
        if let Some(header) = header {
            session.fixed_host_header(header)?;
        }
        let mut graph = Graph::recover_session(session, start)
            .with_context(|| format!("devirtualize {start:?}"))?;
        super::optimize::run(&mut graph)
            .with_context(|| format!("optimize native semantics for {start:?}"))?;
        graph.session.expressions.link_runtime_data(
            graph.session.loader_base,
            profile.runtime_rva,
            loader.len() as u64,
        );
        let mut successors = graph.starts().into_iter().collect::<Vec<_>>();
        successors.sort_unstable();
        pending.extend(successors);
        graphs.push(codegen::RecoveredFunction::from(graph));
    }
    let functions = graphs
        .iter()
        .map(codegen::Function::from)
        .collect::<Vec<_>>();
    let program = codegen::emit(&functions, image_base, rva, &budget)?;
    let blocks = graphs.iter().map(|graph| graph.blocks.len()).sum::<usize>();
    eprintln!(
        "Devirtualized {} VM functions into {} native continuations and {blocks} blocks",
        roots.len(),
        graphs.len()
    );
    Ok(program)
}
