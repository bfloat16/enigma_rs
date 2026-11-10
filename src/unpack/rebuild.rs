//! Architecture dispatch and shared PE import-table construction.
use super::{config::Configuration, extract::Recovered, imports::Import};
use crate::common::{io::put_u32_at, pe::Pe};
use anyhow::{Context, Result, ensure};
use std::borrow::Cow;
use std::collections::BTreeMap;

pub fn rebuild(pe: &Pe<'_>, config: &Configuration, recovered: &[Recovered]) -> Result<Vec<u8>> {
    if pe.is_64 {
        super::x64::rebuild::rebuild(pe, config, recovered)
    } else {
        super::x86::rebuild::rebuild(pe, config, recovered)
    }
}

pub(super) fn align(value: usize, alignment: usize) -> Result<usize> {
    ensure!(alignment.is_power_of_two(), "invalid PE alignment");
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .context("PE alignment overflow")
}

/// Windows copies TLS initializers from the mapped image, including BSS and
/// zero-filled section tails. Other PE readers must still require file data.
pub(super) fn tls_template<'a>(pe: &Pe<'a>, rva: u32, size: usize) -> Result<Cow<'a, [u8]>> {
    if size == 0 {
        return Ok(Cow::Borrowed(&[]));
    }
    let end = u64::from(rva) + size as u64;
    ensure!(
        end <= u64::from(pe.image_size),
        "TLS template outside image"
    );
    if end <= u64::from(pe.headers_size) {
        return Ok(Cow::Borrowed(pe.read(rva, size)?));
    }
    let section = pe
        .section_at(rva)
        .context("TLS template outside mapped sections")?;
    ensure!(
        end <= u64::from(section.rva) + u64::from(section.virtual_size.max(section.raw_size))
            && !pe.sections.iter().any(|s| {
                s.rva > section.rva
                    && u64::from(s.rva) < end
                    && (s.virtual_size != 0 || s.raw_size != 0)
            }),
        "TLS template crosses section boundary"
    );
    let backed = size.min(section.raw_size.saturating_sub(rva - section.rva) as usize);
    if backed == size {
        return Ok(Cow::Borrowed(pe.read(rva, size)?));
    }
    let mut template = vec![0; size];
    if backed != 0 {
        template[..backed].copy_from_slice(pe.read(rva, backed)?);
    }
    Ok(Cow::Owned(template))
}

fn push_string(data: &mut Vec<u8>, text: &str) -> Result<u32> {
    let at = u32::try_from(data.len())?;
    data.extend(text.as_bytes());
    data.push(0);
    Ok(at)
}

pub(super) struct ImportTable {
    pub payload: Vec<u8>,
    pub patches: BTreeMap<u32, u64>,
    pub descriptors_size: usize,
}

/// Preserve original IAT slots and DLL group boundaries for either pointer width.
pub(super) fn import_table(symbols: &[Import], section: u32, is_64: bool) -> Result<ImportTable> {
    let width = if is_64 { 8 } else { 4 };
    let groups = symbols
        .chunk_by(|a, b| a.iat_rva + width == b.iat_rva && a.dll.eq_ignore_ascii_case(&b.dll))
        .collect::<Vec<_>>();
    let descriptors_size = (groups.len() + 1) * 20;
    let mut payload = vec![0; descriptors_size];
    let mut patches = BTreeMap::new();
    for (index, group) in groups.iter().enumerate() {
        let dll = section
            .checked_add(push_string(&mut payload, &group[0].dll)?)
            .context("DLL RVA overflow")?;
        let mut thunks = Vec::with_capacity(group.len());
        for import in *group {
            let thunk = if let Some(name) = &import.name {
                payload.resize(align(payload.len(), 2)?, 0);
                let at = u32::try_from(payload.len())?;
                payload.extend([0, 0]);
                push_string(&mut payload, name)?;
                u64::from(
                    section
                        .checked_add(at)
                        .context("import name RVA overflow")?,
                )
            } else {
                (1u64 << (width * 8 - 1))
                    | u64::from(import.ordinal.context("missing import name/ordinal")?)
            };
            thunks.push(thunk);
            patches.insert(import.iat_rva, thunk);
        }
        payload.resize(align(payload.len(), width as usize)?, 0);
        let ilt = section
            .checked_add(u32::try_from(payload.len())?)
            .context("ILT RVA overflow")?;
        for thunk in thunks.into_iter().chain(std::iter::once(0)) {
            payload.extend(&thunk.to_le_bytes()[..width as usize]);
        }
        put_u32_at(&mut payload, index * 20, ilt)?;
        put_u32_at(&mut payload, index * 20 + 12, dll)?;
        put_u32_at(&mut payload, index * 20 + 16, group[0].iat_rva)?;
        patches.insert(
            group.last().context("empty import group")?.iat_rva + width,
            0,
        );
    }
    Ok(ImportTable {
        payload,
        patches,
        descriptors_size,
    })
}

#[cfg(test)]
#[path = "../../tests/unpack/rebuild.rs"]
mod tests;
