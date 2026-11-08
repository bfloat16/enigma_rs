//! Decode import metadata and resolve Loader VM forwarding slots.
use super::extract::Recovered;
use crate::common::{
    idea::Idea,
    io::{take, u32_at},
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
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn read(&mut self, n: usize) -> Result<&'a [u8]> {
        let bytes = take(self.bytes, self.at, n)?;
        self.at += n;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.read(1)?[0])
    }
    fn word(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read(2)?.try_into()?))
    }
    fn dword(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read(4)?.try_into()?))
    }
    fn name(&mut self, idea: &Idea) -> Result<String> {
        let n = self.word()? as usize;
        ensure!((1..0x8000).contains(&n), "invalid import name length");
        let plain = idea.decrypt(self.read(n)?);
        ensure!(
            plain.iter().all(|b| (32..127).contains(b)),
            "invalid decrypted import name"
        );
        Ok(String::from_utf8(plain)?)
    }
}

pub fn parse_records(
    plain: &[u8],
    key: &[u8; 16],
    flag_size: usize,
    is_64: bool,
) -> Result<Vec<Import>> {
    let idea = Idea::new(key);
    let mut c = Cursor {
        bytes: plain,
        at: 0,
    };
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
            dll = Some(c.name(&idea)?);
            continue;
        }
        let dll = dll.as_ref().context("API record precedes its DLL")?.clone();
        let (name, ordinal) = if flags & 4 != 0 {
            (Some(c.name(&idea)?), None)
        } else {
            let n = if is_64 {
                let value = u64::from_le_bytes(c.read(8)?.try_into()?);
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
        for _ in 0..references {
            let first = c.dword()?;
            let iat_rva = c.dword()?;
            ensure!(
                first == 0,
                "unsupported first import reference field {first:#x}"
            );
            ensure!(
                iat_rva > 0
                    && iat_rva.is_multiple_of(if is_64 { 8 } else { 4 })
                    && slots.insert(iat_rva),
                "invalid or duplicate IAT slot"
            );
            symbols.push(Import {
                dll: dll.clone(),
                name: name.clone(),
                ordinal,
                iat_rva,
            });
        }
        ensure!(symbols.len() <= 65536, "too many import slots");
    }
    ensure!(
        c.at == plain.len() && !symbols.is_empty(),
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
