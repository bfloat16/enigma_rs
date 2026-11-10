//! Resolve x64 runtime API forwarding stubs and import metadata.
use super::super::{
    config::Configuration,
    extract::Recovered,
    imports::{self, Import},
};
use crate::{
    common::{
        codec,
        idea::Idea,
        io::{take, u32_at, u64_at},
        pe::Pe,
    },
    devirt::x64::runtime::Runtime,
};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use std::collections::BTreeSet;

pub(super) fn recover(
    pe: &Pe<'_>,
    config: &Configuration,
    recovered: &[Recovered],
) -> Result<Vec<Import>> {
    let ctx = config.ctx.as_ref().context("x64 context missing")?;
    let layout = config.layout.as_ref().context("x64 layout missing")?;
    let image = config.loader.as_ref().context("x64 runtime missing")?;
    let runtime = Runtime::parse(image)?;
    let data = u32_at(ctx, layout.data)?;
    let fields = layout.data + 0x4c;
    let packed = u32_at(ctx, fields + 4)? as usize;
    let expanded = u32_at(ctx, fields + 8)? as usize;
    ensure!(packed > 0 && expanded > 0, "empty x64 import stream");
    let raw = codec::decompress(
        &Idea::new(&[0; 16]).decrypt(
            pe.read(
                data.checked_add(u32_at(ctx, fields)?)
                    .context("x64 import offset overflow")?,
                packed,
            )?,
        ),
        expanded,
        true,
    )
    .context("x64 import buffer decode")?;
    let mut result = None;
    let mut key = None;
    // Every name and ordinal, reference, terminator and stream byte must verify.
    // A key is accepted only if the complete import record set is unambiguous.
    for candidate in ctx.windows(16) {
        if let Ok(imports) = imports::parse_records(&raw, candidate.try_into()?, 1, true) {
            ensure!(
                key.as_deref().is_none_or(|old: &[u8]| old == candidate),
                "ambiguous x64 import name key"
            );
            key = Some(candidate.to_vec());
            result = Some(imports);
        }
    }
    let mut symbols = result.context("x64 import name verification failed")?;
    let hooks = runtime.hooks(image)?;
    let engine = imports::engine_section(pe, image)?;
    let slots: BTreeSet<_> = symbols.iter().map(|s| s.iat_rva).collect();
    let min = *slots.first().context("no x64 imports")?;
    let max = *slots.last().context("no x64 imports")?;
    for slot in (min..=max).step_by(8) {
        let value = u64_at(imports::recovered_read(recovered, slot, 8)?, 0)?;
        if slots.contains(&slot) || value == 0 {
            continue;
        }
        let mut target = u32::try_from(
            value
                .checked_sub(pe.image_base + engine.rva as u64)
                .context("x64 IAT gap outside runtime")?,
        )?;
        let mut found = None;
        for _ in 0..16 {
            if let Some(pair) = hooks.get(&target) {
                found = Some(pair.clone());
                break;
            }
            let i = Decoder::with_ip(
                64,
                take(image, target as usize, 5)?,
                target as u64,
                DecoderOptions::NONE,
            )
            .decode();
            ensure!(
                i.mnemonic() == Mnemonic::Jmp && i.op0_kind() == OpKind::NearBranch64,
                "unsupported x64 API forwarding stub"
            );
            target = u32::try_from(i.near_branch64())?;
        }
        let (dll, name) = found.context("x64 API stub is not registered")?;
        symbols.push(Import {
            dll,
            name: Some(name),
            ordinal: None,
            iat_rva: slot,
        });
    }
    symbols.sort_by_key(|s| s.iat_rva);
    for (index, s) in symbols.iter().enumerate() {
        ensure!(s.iat_rva.is_multiple_of(8), "unaligned x64 IAT slot");
        if symbols.get(index + 1).is_none_or(|next| {
            next.iat_rva != s.iat_rva + 8 || !next.dll.eq_ignore_ascii_case(&s.dll)
        }) {
            ensure!(
                u64_at(imports::recovered_read(recovered, s.iat_rva + 8, 8)?, 0)? == 0,
                "x64 IAT group lacks null terminator"
            );
        }
    }
    Ok(symbols)
}
