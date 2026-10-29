//! Replace VM entries and native continuations with input-derived machine code.
use super::{
    codegen,
    graph::{Graph, Start},
    switch::Session,
    vm::{Profile, Tokens},
};
use crate::{common::io::put_u32_at, unpack::extract::Recovered};
use anyhow::{Context, Result, ensure};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

pub(crate) struct Native {
    pub patches: Vec<Recovered>,
    pub relocations: Vec<u32>,
}

pub(crate) fn append(
    loader: &[u8],
    header: &[u8],
    entry: u32,
    host_end: u32,
    image_base: u32,
    section: u32,
    payload: &mut Vec<u8>,
) -> Result<Native> {
    let tokens = Tokens::parse(loader)?;
    let profile = Arc::new(Profile::parse(&tokens)?);
    let roots = profile
        .streams
        .iter()
        .filter(|s| s.0 < host_end)
        .map(|s| s.0)
        .collect::<Vec<_>>();
    ensure!(roots.contains(&entry), "VM entry is not a host stream");
    let offset = payload.len().div_ceil(16) * 16;
    let rva = section
        .checked_add(offset.try_into()?)
        .context("native payload RVA overflow")?;
    let program = compile(
        loader,
        Some(header),
        profile,
        &roots,
        entry,
        image_base,
        rva,
    )?;
    payload.resize(offset, 0);
    payload.extend(&program.bytes);
    let mut patches = Vec::new();
    for &source in &roots {
        let target = program.entries[&Start::Function(source)];
        let mut bytes = vec![0xe9, 0, 0, 0, 0];
        put_u32_at(&mut bytes, 1, target.wrapping_sub(source + 5))?;
        patches.push(Recovered { rva: source, bytes });
    }
    Ok(Native {
        patches,
        relocations: program.relocations,
    })
}

pub(super) fn compile(
    loader: &[u8],
    header: Option<&[u8]>,
    profile: Arc<Profile>,
    roots: &[u32],
    entry: u32,
    image_base: u32,
    rva: u32,
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
        let mut successors = graph.starts().into_iter().collect::<Vec<_>>();
        successors.sort_unstable();
        pending.extend(successors);
        graphs.push(graph);
    }
    let functions = graphs
        .iter()
        .map(codegen::Function::from)
        .collect::<Vec<_>>();
    let program = codegen::emit_with_budget(&functions, image_base, rva, &budget)?;
    let blocks = graphs.iter().map(|graph| graph.blocks.len()).sum::<usize>();
    eprintln!(
        "Devirtualized {} VM functions into {} native continuations and {blocks} blocks",
        roots.len(),
        graphs.len()
    );
    Ok(program)
}
