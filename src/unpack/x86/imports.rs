//! Resolve x86 Loader token forwarding slots and import metadata.
use super::super::{
    config::Configuration,
    extract::Recovered,
    imports::{Import, engine_section, parse_records, recovered_read},
};
use crate::{
    common::{
        codec,
        idea::Idea,
        io::{take, u32_at},
        pe::Pe,
    },
    devirt::x86::vm,
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

pub(super) fn recover(
    pe: &Pe<'_>,
    config: &Configuration,
    recovered: &[Recovered],
) -> Result<Vec<Import>> {
    ensure!(
        !pe.is_64,
        "OEP/IAT reconstruction currently supports x86 only"
    );
    let ctx = config.ctx.as_ref().context("unknown ctx layout")?;
    let layout = config.layout.as_ref().context("unknown Loader layout")?;
    let image = config.loader.as_ref().context("no Loader")?;
    let tokens = vm::Tokens::parse(image)?;
    let fields = tokens.import_fields(layout.data, layout.entry, ctx.len())?;
    let metadata_rva = u32_at(ctx, layout.data)?
        .checked_add(u32_at(ctx, fields.descriptor)?)
        .context("import RVA overflow")?;
    let packed_size =
        crate::common::codec::expanded_size(u32_at(ctx, fields.descriptor + 4)? as usize)?;
    let expanded =
        crate::common::codec::expanded_size(u32_at(ctx, fields.descriptor + 8)? as usize)?;
    let key: [u8; 16] = take(ctx, fields.name_key, 16)?.try_into()?;
    ensure!(ctx[fields.name_key - 1] >= 16, "short import name key");
    // The constructor clears ctx+4. A registration-check branch XORs its
    // serialized 16-byte key into that buffer. Explore both defined states;
    // complete LZ, record and name validation must establish one result.
    let mut keys = vec![[0; 16]];
    if let Some(at) = fields.license_key {
        let license = take(ctx, at, 16)?.try_into()?;
        if license != keys[0] {
            keys.push(license);
        }
    }
    let cipher = pe.read(metadata_rva, packed_size)?;
    let mut decoded = None;
    let mut errors = Vec::new();
    for buffer_key in keys {
        let result = (|| -> Result<Vec<Import>> {
            let packed = Idea::new(&buffer_key).decrypt(cipher);
            let plain = codec::decompress(&packed, expanded, true)?;
            parse_records(&plain, &key, fields.flag_size, false)
        })();
        match result {
            Ok(symbols) => {
                ensure!(decoded.is_none(), "ambiguous import key branch");
                decoded = Some(symbols);
            }
            Err(e) => errors.push(e.to_string()),
        }
    }
    let mut symbols = decoded
        .with_context(|| format!("Loader import key branches failed: {}", errors.join("; ")))?;
    let engine = engine_section(pe, image)?;
    let engine_va = u32::try_from(pe.image_base)?
        .checked_add(engine.rva)
        .context("engine VA overflow")?;
    let names = tokens.hooks()?;
    let slots: BTreeSet<_> = symbols.iter().map(|s| s.iat_rva).collect();
    let min = *slots.first().context("no IAT slots")?;
    let max = *slots.last().context("no IAT slots")?;
    ensure!(max - min <= 0x100000, "oversized IAT range");
    let mut zeros = BTreeSet::new();
    for slot in (min..=max).step_by(4) {
        let value = u32_at(recovered_read(recovered, slot, 4)?, 0)?;
        if slots.contains(&slot) {
            continue;
        }
        if value == 0 {
            zeros.insert(slot);
            continue;
        }
        let stub = value
            .checked_sub(engine_va)
            .context("unidentified nonzero IAT gap")?;
        let token = vm::stub_token_at(image, stub, tokens.key, tokens.dispatch)?;
        let (dll, name) = names
            .get(&token)
            .context("IAT stub is not a registered API Hook")?;
        symbols.push(Import {
            dll: dll.clone(),
            name: Some(name.clone()),
            ordinal: None,
            iat_rva: slot,
        });
    }
    symbols.sort_by_key(|s| s.iat_rva);
    let expected: BTreeSet<_> = symbols
        .windows(2)
        .filter(|pair| {
            pair[0].iat_rva + 4 != pair[1].iat_rva
                || !pair[0].dll.eq_ignore_ascii_case(&pair[1].dll)
        })
        .map(|pair| pair[0].iat_rva + 4)
        .collect();
    ensure!(
        expected.is_subset(&zeros),
        "IAT group lacks a zero terminator"
    );
    // Include and verify the final group's terminating null thunk as well.
    ensure!(
        u32_at(recovered_read(recovered, max + 4, 4)?, 0)? == 0,
        "last IAT group lacks a zero terminator"
    );
    Ok(symbols)
}
