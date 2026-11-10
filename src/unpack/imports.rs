//! Decode import metadata and resolve Loader VM forwarding slots.
use super::extract::Recovered;
use crate::common::{
    idea::Idea,
    io::{Cursor, take, u32_at},
    pe::Pe,
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct Import {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_rva: u32,
}

fn decrypt_name(c: &mut Cursor<'_>, idea: &Idea) -> Result<String> {
    let n = c.word()? as usize;
    ensure!(n > 0, "empty import name");
    let plain = idea.decrypt(c.read(n)?);
    ensure!(
        plain.iter().all(|b| (32..127).contains(b)),
        "invalid decrypted import name"
    );
    Ok(String::from_utf8(plain)?)
}

pub fn parse_records(
    plain: &[u8],
    key: &[u8; 16],
    flag_size: usize,
    is_64: bool,
) -> Result<Vec<Import>> {
    parse_records_with(plain, key, flag_size, is_64, |references| {
        Ok(references.to_vec())
    })
}

/// Resolve architecture-specific references before validating unique IAT slots.
pub(super) fn parse_records_with(
    plain: &[u8],
    key: &[u8; 16],
    flag_size: usize,
    is_64: bool,
    mut resolve: impl FnMut(&[u32]) -> Result<Vec<u32>>,
) -> Result<Vec<Import>> {
    let idea = Idea::new(key);
    let mut c = Cursor::new(plain);
    let mut dll = None;
    let mut symbols = Vec::new();
    let mut slots = BTreeSet::new();
    loop {
        let flags = if flag_size == 4 {
            c.dword()?
        } else {
            c.byte()? as u32
        };
        if flags == 255 || flags == u32::MAX {
            break;
        }
        if flags & 1 != 0 {
            dll = Some(decrypt_name(&mut c, &idea)?);
            continue;
        }
        let dll = dll.as_ref().context("API record precedes its DLL")?.clone();
        let (name, ordinal) = if flags & 4 != 0 {
            (Some(decrypt_name(&mut c, &idea)?), None)
        } else {
            let n = if is_64 {
                let value = c.qword()?;
                ensure!(
                    value & 0x7fff_ffff_ffff_0000 == 0,
                    "invalid x64 import ordinal"
                );
                value as u32
            } else {
                c.dword()? & 0x7fffffff
            };
            ensure!(n <= u16::MAX as u32, "invalid import ordinal");
            (None, Some(n as u16))
        };
        let references = c.word()?;
        ensure!(references > 0, "API record has no references");
        let mut rvas = Vec::with_capacity(references as usize);
        for _ in 0..references {
            let first = c.dword()?;
            let iat_rva = c.dword()?;
            ensure!(
                first == 0,
                "unsupported first import reference field {first:#x}"
            );
            rvas.push(iat_rva);
        }
        let resolved = resolve(&rvas)?;
        ensure!(!resolved.is_empty(), "API record has no IAT slots");
        for iat_rva in resolved {
            ensure!(
                iat_rva > 0
                    && iat_rva.is_multiple_of(if is_64 { 8 } else { 4 })
                    && slots.insert(iat_rva),
                "invalid or duplicate IAT slot {iat_rva:#x}"
            );
            symbols.push(Import {
                dll: dll.clone(),
                name: name.clone(),
                ordinal,
                iat_rva,
            });
        }
    }
    ensure!(
        c.position() == plain.len() && !symbols.is_empty(),
        "incomplete import record consumption"
    );
    Ok(symbols)
}

pub fn recovered_read(recovered: &[Recovered], rva: u32, size: usize) -> Result<&[u8]> {
    let section = recovered
        .iter()
        .find(|s| rva >= s.rva && ((rva - s.rva) as usize) < s.bytes.len())
        .context("RVA outside recovered sections")?;
    take(&section.bytes, (rva - section.rva) as usize, size)
}

pub fn engine_section<'a>(pe: &'a Pe<'_>, image: &[u8]) -> Result<&'a crate::common::pe::Section> {
    let size = u32_at(image, u32_at(image, 0x3c)? as usize + 80)?;
    let candidates: Vec<_> = pe
        .sections
        .iter()
        .filter(|s| s.virtual_size == size)
        .collect();
    ensure!(
        candidates.len() == 1,
        "cannot uniquely locate original Loader mapping"
    );
    Ok(candidates[0])
}

#[cfg(test)]
#[path = "../../tests/unpack/imports.rs"]
mod tests;
