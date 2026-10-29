//! Rebuild host PE sections, original IAT slots, relocations and native startup.
use super::{config::Configuration, extract::Recovered, imports};
use crate::{
    common::{
        codec,
        io::{put_u32_at as put, take, u16_at, u32_at},
        pe::{Pe, checksum},
    },
    devirt::{native, vm},
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;

fn align(value: usize, alignment: usize) -> Result<usize> {
    ensure!(alignment.is_power_of_two(), "invalid PE alignment");
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .context("PE alignment overflow")
}
fn push_string(data: &mut Vec<u8>, text: &str) -> Result<u32> {
    let at = u32::try_from(data.len())?;
    data.extend(text.as_bytes());
    data.push(0);
    Ok(at)
}

fn original_section_flags(
    pe: &Pe<'_>,
    descriptors: &[super::config::Descriptor],
    host_end: u32,
) -> Result<BTreeMap<u32, u32>> {
    let mut flags = BTreeMap::new();
    for descriptor in descriptors.iter().take_while(|d| d.rva != 0) {
        ensure!(
            descriptor.rva < host_end && pe.sections.iter().any(|s| s.rva == descriptor.rva),
            "section descriptor RVA {:#x} is not a retained host section start",
            descriptor.rva
        );
        ensure!(
            flags
                .insert(descriptor.rva, descriptor.characteristics)
                .is_none(),
            "duplicate section attributes at RVA {:#x}",
            descriptor.rva
        );
    }
    Ok(flags)
}

fn relocations(
    pe: &Pe<'_>,
    ctx: &[u8],
    layout: &vm::Layout,
    host_end: u32,
    extra: &[u32],
) -> Result<(Vec<u8>, usize)> {
    let packed = u32_at(ctx, layout.relocations + 4)? as usize;
    let expanded = u32_at(ctx, layout.relocations + 8)? as usize;
    if packed == 0 && expanded == 0 {
        return Ok((Vec::new(), 0));
    }
    let rva = u32_at(ctx, layout.data)?
        .checked_add(u32_at(ctx, layout.relocations)?)
        .context("relocation RVA overflow")?;
    let bytes = codec::decompress(
        pe.read(rva, crate::common::codec::expanded_size(packed)?)?,
        crate::common::codec::expanded_size(expanded)?,
        true,
    )?;
    let mut p = 0;
    let mut count = 0;
    while p < bytes.len() {
        let page = u32_at(&bytes, p)?;
        let n = u32_at(&bytes, p + 4)? as usize;
        if page == 0 && n == 0 {
            ensure!(
                bytes[p..].iter().all(|&b| b == 0),
                "nonzero relocation tail"
            );
            break;
        }
        ensure!(n >= 8 && n.is_multiple_of(2), "invalid relocation block");
        take(&bytes, p, n)?;
        for at in (p + 8..p + n).step_by(2) {
            let value = u16_at(&bytes, at)?;
            let kind = value >> 12;
            ensure!(
                kind == 0 || kind == 3,
                "unsupported x86 relocation type {kind}"
            );
            if kind == 3 {
                ensure!(
                    page as u64 + (value & 0xfff) as u64 + 4 <= host_end as u64,
                    "relocation points outside host image"
                );
                count += 1;
            }
        }
        p += n;
    }
    let mut bytes = bytes[..p].to_vec();
    let mut pages = BTreeMap::<u32, Vec<u16>>::new();
    for &rva in extra {
        pages
            .entry(rva & !0xfff)
            .or_default()
            .push(0x3000 | (rva & 0xfff) as u16);
        count += 1;
    }
    for (page, mut entries) in pages {
        if !entries.len().is_multiple_of(2) {
            entries.push(0);
        }
        bytes.extend(page.to_le_bytes());
        bytes.extend((8 + entries.len() as u32 * 2).to_le_bytes());
        for entry in entries {
            bytes.extend(entry.to_le_bytes());
        }
    }
    Ok((bytes, count))
}

fn append_tls(
    pe: &Pe<'_>,
    ctx: &[u8],
    tls_fields: usize,
    host_end: u32,
    section_rva: u32,
    payload: &mut Vec<u8>,
) -> Result<(u32, Vec<u32>)> {
    let index = u32_at(ctx, tls_fields)?;
    if index == 0 {
        return Ok((0, Vec::new()));
    }
    ensure!(
        index as u64 + 4 <= host_end as u64
            && pe
                .section_at(index)
                .is_some_and(|s| s.characteristics & 0x80000000 != 0),
        "original TLS index is outside writable host data"
    );
    let directory = pe.optional + 96 + 9 * 8;
    let rva = u32_at(pe.data, directory)?;
    ensure!(
        rva != 0 && u32_at(pe.data, directory + 4)? >= 24,
        "missing protected TLS directory"
    );
    let tls = pe.read(rva, 24)?;
    let base = u32::try_from(pe.image_base)?;
    let to_rva = |va: u32| va.checked_sub(base).context("TLS address below image base");
    ensure!(
        to_rva(u32_at(tls, 8)?)? == u32_at(ctx, tls_fields + 4)?,
        "protected TLS index does not match Loader context"
    );
    let start = u32_at(tls, 0)?;
    let length = u32_at(tls, 4)?
        .checked_sub(start)
        .context("invalid TLS template range")? as usize;
    let template = if length == 0 {
        &[][..]
    } else {
        pe.read(to_rva(start)?, length)?
    };
    let zero_fill = u32_at(tls, 16)?;
    ensure!(
        length as u64 + zero_fill as u64 <= crate::common::codec::MAX_EXPANDED as u64,
        "TLS template too large"
    );
    let characteristics = u32_at(tls, 20)?;
    let mut callbacks = Vec::new();
    if u32_at(tls, 12)? != 0 {
        let mut slot = to_rva(u32_at(tls, 12)?)?;
        loop {
            let callback = u32_at(pe.read(slot, 4)?, 0)?;
            if callback == 0 {
                break;
            }
            let callback_rva = to_rva(callback)?;
            ensure!(
                callback_rva < host_end
                    && pe
                        .section_at(callback_rva)
                        .is_some_and(|s| s.characteristics & 0x20000000 != 0),
                "TLS callback points into the removed Loader"
            );
            callbacks.push(callback);
            slot = slot
                .checked_add(4)
                .context("TLS callback address overflow")?;
        }
    }
    payload.resize(align(payload.len(), 4)?, 0);
    let at = payload.len();
    let tls_rva = section_rva
        .checked_add(u32::try_from(at)?)
        .context("TLS RVA overflow")?;
    payload.resize(at + 24, 0);
    let callback_rva = section_rva + payload.len() as u32;
    let mut fixups: Vec<u32> = (0..4).map(|i| tls_rva + i * 4).collect();
    for callback in callbacks {
        fixups.push(section_rva + payload.len() as u32);
        payload.extend(callback.to_le_bytes());
    }
    payload.extend(0u32.to_le_bytes());
    let alignment = (characteristics >> 20) & 15;
    let alignment = if alignment == 0 {
        4
    } else {
        1 << (alignment - 1)
    };
    payload.resize(align(payload.len(), alignment)?, 0);
    let template_rva = section_rva + payload.len() as u32;
    payload.extend(template);
    // The Loader keeps the original template, but redirects AddressOfIndex.
    // Have Windows populate the host's index and TLS block before native startup.
    put(payload, at, base + template_rva)?;
    put(payload, at + 4, base + template_rva + length as u32)?;
    put(payload, at + 8, base + index)?;
    put(payload, at + 12, base + callback_rva)?;
    put(payload, at + 16, zero_fill)?;
    put(payload, at + 20, characteristics)?;
    Ok((tls_rva, fixups))
}

pub fn rebuild(pe: &Pe<'_>, config: &Configuration, recovered: &[Recovered]) -> Result<Vec<u8>> {
    ensure!(
        !pe.is_64,
        "rebuild supports the validated x86 Loader profile"
    );
    let ctx = config.ctx.as_ref().context("ctx missing")?;
    let layout = config.layout.as_ref().context("unknown Loader layout")?;
    let loader = config.loader.as_ref().context("Loader missing")?;
    let imports = imports::recover(pe, config, recovered)?;
    let engine = imports::engine_section(pe, loader)?;
    let host: Vec<_> = pe.sections.iter().filter(|s| s.rva < engine.rva).collect();
    let host_end = host
        .iter()
        .map(|s| s.rva as u64 + s.virtual_size.max(s.raw_size) as u64)
        .max()
        .context("no host PE sections")?;
    let host_end = u32::try_from(host_end)?;
    let section_flags = original_section_flags(pe, &config.descriptors, host_end)?;
    let encrypted_entry = layout
        .entry_cipher
        .as_ref()
        .map(|cipher| -> Result<u32> {
            let source = u32_at(ctx, layout.data)?
                .checked_add(u32_at(ctx, cipher.offset)?)
                .and_then(|rva| rva.checked_add(cipher.bias))
                .context("entry key source RVA overflow")?;
            let size = u32_at(ctx, cipher.length)? as usize;
            ensure!(size != 0, "empty entry key source");
            let key = md5::compute(pe.read(source, size)?).0;
            ensure!(
                key == take(ctx, cipher.digest, 16)?,
                "entry key digest mismatch"
            );
            u32_at(
                &crate::common::idea::Idea::new(&key).decrypt(take(ctx, layout.entry, 4)?),
                0,
            )
        })
        .transpose()?;
    let entry_mode = if encrypted_entry.is_some() {
        0
    } else {
        u32_at(ctx, layout.entry)?
    };
    ensure!(
        entry_mode == 0 || entry_mode == 2,
        "unsupported original entry protection mode {entry_mode}"
    );
    let entry_rva = if let Some(rva) = encrypted_entry {
        rva
    } else if entry_mode == 0 {
        u32_at(ctx, layout.entry + 8)?
    } else {
        u32_at(ctx, layout.entry + 4)?
            .checked_sub(5)
            .context("entry RVA underflow")?
    };
    ensure!(
        entry_rva < host_end
            && pe.section_at(entry_rva).is_some_and(|s| {
                section_flags
                    .get(&s.rva)
                    .copied()
                    .unwrap_or(s.characteristics)
                    & 0x20000000
                    != 0
            }),
        "original entry outside executable host code"
    );
    if entry_mode == 2 {
        ensure!(
            u32_at(ctx, layout.entry + 8)?
                == engine
                    .rva
                    .checked_add(layout.trampoline)
                    .context("entry trampoline overflow")?,
            "unexpected original entry trampoline"
        );
    }
    let section_alignment = u32_at(pe.data, pe.optional + 32)? as usize;
    ensure!(
        (0x200..=0x100000).contains(&section_alignment),
        "unsupported SectionAlignment"
    );
    let section_rva = u32::try_from(align(host_end as usize, section_alignment)?)?;
    let mut groups: Vec<Vec<&crate::unpack::imports::Import>> = Vec::new();
    for import in &imports {
        if groups.last().is_none_or(|g| {
            g.last().is_none_or(|last| {
                last.dll.to_lowercase() != import.dll.to_lowercase()
                    || last.iat_rva + 4 != import.iat_rva
            })
        }) {
            groups.push(Vec::new());
        }
        groups.last_mut().context("no import group")?.push(import);
    }
    let descriptors_size = (groups.len() + 1) * 20;
    let mut payload = vec![0; descriptors_size];
    let mut patches = BTreeMap::new();
    for (i, group) in groups.iter().enumerate() {
        let dll = section_rva
            .checked_add(push_string(&mut payload, &group[0].dll)?)
            .context("DLL RVA overflow")?;
        let mut thunks = Vec::new();
        for import in group {
            let thunk = if let Some(name) = &import.name {
                if !payload.len().is_multiple_of(2) {
                    payload.push(0);
                }
                let at = u32::try_from(payload.len())?;
                payload.extend([0, 0]);
                push_string(&mut payload, name)?;
                section_rva
                    .checked_add(at)
                    .context("import name RVA overflow")?
            } else {
                0x80000000 | import.ordinal.context("missing import name/ordinal")? as u32
            };
            thunks.push(thunk);
            patches.insert(import.iat_rva, thunk);
        }
        payload.resize(align(payload.len(), 4)?, 0);
        let ilt = section_rva
            .checked_add(u32::try_from(payload.len())?)
            .context("ILT RVA overflow")?;
        for thunk in thunks {
            payload.extend(thunk.to_le_bytes());
        }
        payload.extend(0u32.to_le_bytes());
        put(&mut payload, i * 20, ilt)?;
        put(&mut payload, i * 20 + 12, dll)?;
        put(&mut payload, i * 20 + 16, group[0].iat_rva)?;
        patches.insert(group.last().context("empty import group")?.iat_rva + 4, 0);
    }
    for (&rva, &thunk) in &patches {
        if rva >= section_rva {
            put(&mut payload, (rva - section_rva) as usize, thunk)?;
        }
    }
    let native_entry = entry_mode == 2;
    let (entry_patches, native_relocations) = if native_entry {
        let native = native::append(
            loader,
            take(pe.data, 0, pe.headers_size as usize)?,
            entry_rva,
            host_end,
            pe.image_base.try_into()?,
            section_rva,
            &mut payload,
        )
        .context("VM devirtualization did not produce a native entry")?;
        (native.patches, native.relocations)
    } else {
        (Vec::new(), Vec::new())
    };
    let (tls_rva, mut tls_fixups) =
        append_tls(pe, ctx, layout.tls, host_end, section_rva, &mut payload)?;
    tls_fixups.extend(native_relocations);
    let (relocs, relocation_count) = relocations(pe, ctx, layout, host_end, &tls_fixups)?;
    payload.resize(align(payload.len(), 4)?, 0);
    let reloc_rva = section_rva
        .checked_add(u32::try_from(payload.len())?)
        .context("relocation section overflow")?;
    payload.extend(&relocs);
    let count = host.len() + 1;
    let table = pe.optional + u16_at(pe.data, pe.nt + 20)? as usize;
    ensure!(
        table + count * 40 <= pe.headers_size as usize,
        "insufficient PE header space"
    );
    let mut output = take(pe.data, 0, pe.headers_size as usize)?.to_vec();
    output[table..].fill(0);
    let mut initialized = 0u32;
    let mut code = 0u32;
    for (i, section) in host.iter().enumerate() {
        let restored = recovered.iter().find(|s| s.rva == section.rva);
        let mut bytes = if let Some(s) = restored {
            s.bytes.clone()
        } else if section.raw_size > 0 {
            pe.read(section.rva, section.raw_size as usize)?.to_vec()
        } else {
            Vec::new()
        };
        for patch in &entry_patches {
            if patch.rva >= section.rva && patch.rva < section.rva + bytes.len() as u32 {
                let at = (patch.rva - section.rva) as usize;
                take(&bytes, at, patch.bytes.len())?;
                bytes[at..at + patch.bytes.len()].copy_from_slice(&patch.bytes);
            }
        }
        for (&rva, &thunk) in &patches {
            if rva >= section.rva && rva as u64 + 4 <= section.rva as u64 + bytes.len() as u64 {
                put(&mut bytes, (rva - section.rva) as usize, thunk)?;
            }
        }
        let at = table + i * 40;
        output[at..at + 40].copy_from_slice(take(pe.data, section.header_offset, 40)?);
        let characteristics = section_flags
            .get(&section.rva)
            .copied()
            .unwrap_or(section.characteristics);
        put(&mut output, at + 36, characteristics)?;
        let offset = align(output.len(), pe.file_alignment as usize)?;
        let raw = align(bytes.len(), pe.file_alignment as usize)?;
        ensure!(
            offset
                .checked_add(raw)
                .is_some_and(|e| e <= crate::common::codec::MAX_EXPANDED),
            "rebuilt PE too large"
        );
        output.resize(offset + raw, 0);
        output[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let virtual_size = section.virtual_size.max(u32::try_from(bytes.len())?);
        put(&mut output, at + 8, virtual_size)?;
        put(&mut output, at + 16, raw as u32)?;
        put(
            &mut output,
            at + 20,
            if raw == 0 { 0 } else { offset as u32 },
        )?;
        if characteristics & 0x20 != 0 {
            code = code.checked_add(raw as u32).context("code size overflow")?;
        } else {
            initialized = initialized
                .checked_add(raw as u32)
                .context("data size overflow")?;
        }
    }
    let offset = align(output.len(), pe.file_alignment as usize)?;
    let raw = align(payload.len(), pe.file_alignment as usize)?;
    ensure!(
        offset + raw <= crate::common::codec::MAX_EXPANDED,
        "rebuilt PE too large"
    );
    let at = table + host.len() * 40;
    output[at..at + 8].copy_from_slice(b".rebuild");
    put(&mut output, at + 8, payload.len() as u32)?;
    put(&mut output, at + 12, section_rva)?;
    put(&mut output, at + 16, raw as u32)?;
    put(&mut output, at + 20, offset as u32)?;
    put(
        &mut output,
        at + 36,
        if native_entry { 0x60000060 } else { 0xc0000040 },
    )?;
    output.resize(offset + raw, 0);
    output[offset..offset + payload.len()].copy_from_slice(&payload);
    output[pe.nt + 6..pe.nt + 8].copy_from_slice(&(count as u16).to_le_bytes());
    let characteristics = u16_at(pe.data, pe.nt + 22)?;
    output[pe.nt + 22..pe.nt + 24].copy_from_slice(
        &(if relocs.is_empty() {
            characteristics | 1
        } else {
            characteristics & !1
        })
        .to_le_bytes(),
    );
    put(
        &mut output,
        pe.optional + 4,
        if native_entry {
            code + raw as u32
        } else {
            code
        },
    )?;
    put(&mut output, pe.optional + 8, initialized + raw as u32)?;
    put(&mut output, pe.optional + 16, entry_rva)?;
    put(
        &mut output,
        pe.optional + 56,
        u32::try_from(align(
            section_rva as usize + payload.len(),
            section_alignment,
        )?)?,
    )?;
    let flags = u16_at(&output, pe.optional + 70)? & !0x4040;
    output[pe.optional + 70..pe.optional + 72].copy_from_slice(&flags.to_le_bytes());
    let directory = pe.optional + 96;
    let n = u32_at(pe.data, directory - 4)? as usize;
    ensure!(
        n >= 13 && directory + n * 8 <= pe.optional + u16_at(pe.data, pe.nt + 20)? as usize,
        "missing PE directories"
    );
    let resource = (
        u32_at(pe.data, directory + 16)?,
        u32_at(pe.data, directory + 20)?,
    );
    output[directory..directory + n * 8].fill(0);
    put(&mut output, directory + 8, section_rva)?;
    put(&mut output, directory + 12, descriptors_size as u32)?;
    if resource.0 != 0 {
        ensure!(
            resource.0 as u64 + resource.1 as u64 <= host_end as u64,
            "resource directory outside host"
        );
        put(&mut output, directory + 16, resource.0)?;
        put(&mut output, directory + 20, resource.1)?;
    }
    if !relocs.is_empty() {
        put(&mut output, directory + 40, reloc_rva)?;
        put(&mut output, directory + 44, relocs.len() as u32)?;
    }
    if tls_rva != 0 {
        put(&mut output, directory + 72, tls_rva)?;
        put(&mut output, directory + 76, 24)?;
    }
    let min = *patches.first_key_value().context("no IAT patches")?.0;
    let max = *patches.last_key_value().context("no IAT patches")?.0;
    put(&mut output, directory + 96, min)?;
    put(&mut output, directory + 100, max - min + 4)?;
    put(&mut output, pe.optional + 64, 0)?;
    let checksum = checksum(&output, pe.optional + 64);
    put(&mut output, pe.optional + 64, checksum)?;
    eprintln!(
        "Rebuilt OEP {:#x}, {} imports, {relocation_count} relocations",
        entry_rva,
        imports.len()
    );
    Ok(output)
}

#[cfg(test)]
#[path = "../../test/rebuild.rs"]
mod tests;
