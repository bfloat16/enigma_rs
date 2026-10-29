//! Decode import metadata and resolve Loader VM forwarding slots.
use super::{config::Configuration, extract::Recovered};
use crate::{
    common::{
        codec,
        idea::Idea,
        io::{take, u32_at},
        pe::Pe,
    },
    devirt::vm,
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

pub fn parse_records(plain: &[u8], key: &[u8; 16], flag_size: usize) -> Result<Vec<Import>> {
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
            let n = c.dword()? & 0x7fffffff;
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
                iat_rva > 0 && iat_rva.is_multiple_of(4) && slots.insert(iat_rva),
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
pub fn recover(
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
            parse_records(&plain, &key, fields.flag_size)
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
