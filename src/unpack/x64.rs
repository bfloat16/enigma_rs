//! PE32+ recovery for the verified x64 serialized reader and native startup ABI.
use super::{
    config::Configuration,
    extract::Recovered,
    imports::{self, Import},
};
use crate::{
    common::{
        codec,
        idea::Idea,
        io::{put_u32_at as put, take, u16_at, u32_at, u64_at},
        pe::{Pe, checksum},
    },
    devirt::x64::Runtime,
};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use std::collections::{BTreeMap, BTreeSet};

fn recover_imports(
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
    let expanded = codec::expanded_size(u32_at(ctx, fields + 8)? as usize)?;
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
        if let Ok(imports) = imports::parse_records_arch(&raw, candidate.try_into()?, 1, true) {
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
    let max = *slots.last().unwrap();
    ensure!(max - min <= 0x100000, "oversized x64 IAT");
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
fn align(n: usize, a: usize) -> Result<usize> {
    ensure!(a.is_power_of_two(), "invalid x64 alignment");
    n.checked_add(a - 1)
        .map(|v| v & !(a - 1))
        .context("x64 alignment overflow")
}
fn put64(b: &mut [u8], at: usize, v: u64) -> Result<()> {
    take(b, at, 8)?;
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn string(b: &mut Vec<u8>, s: &str) -> Result<u32> {
    let at = u32::try_from(b.len())?;
    b.extend(s.as_bytes());
    b.push(0);
    Ok(at)
}

pub(super) fn rebuild(
    pe: &Pe<'_>,
    config: &Configuration,
    recovered: &[Recovered],
) -> Result<Vec<u8>> {
    let ctx = config.ctx.as_ref().context("x64 context missing")?;
    let layout = config.layout.as_ref().context("x64 layout missing")?;
    let loader = config.loader.as_ref().context("x64 runtime missing")?;
    let engine = imports::engine_section(pe, loader)?;
    let host: Vec<_> = pe.sections.iter().filter(|s| s.rva < engine.rva).collect();
    let host_end = engine.rva;
    let section_alignment = u32_at(pe.data, pe.optional + 32)? as usize;
    ensure!(
        (0x200..=0x100000).contains(&section_alignment),
        "unsupported x64 section alignment"
    );
    let section_rva = u32::try_from(align(host_end as usize, section_alignment)?)?;
    let symbols = recover_imports(pe, config, recovered)?;
    let mut groups: Vec<Vec<&Import>> = Vec::new();
    for s in &symbols {
        if groups.last().is_none_or(|g| {
            g.last()
                .is_none_or(|p| p.iat_rva + 8 != s.iat_rva || !p.dll.eq_ignore_ascii_case(&s.dll))
        }) {
            groups.push(Vec::new());
        }
        groups.last_mut().unwrap().push(s);
    }
    let descriptors = (groups.len() + 1) * 20;
    let mut payload = vec![0; descriptors];
    let mut patches = BTreeMap::new();
    for (index, group) in groups.iter().enumerate() {
        let dll = section_rva + string(&mut payload, &group[0].dll)?;
        let mut thunks = Vec::new();
        for import in group {
            let thunk = if let Some(name) = &import.name {
                payload.resize(align(payload.len(), 2)?, 0);
                let rva = section_rva + u32::try_from(payload.len())?;
                payload.extend([0, 0]);
                string(&mut payload, name)?;
                rva as u64
            } else {
                0x8000000000000000 | import.ordinal.context("missing x64 import ordinal")? as u64
            };
            thunks.push(thunk);
            patches.insert(import.iat_rva, thunk);
        }
        payload.resize(align(payload.len(), 8)?, 0);
        let ilt = section_rva + u32::try_from(payload.len())?;
        for thunk in thunks {
            payload.extend(thunk.to_le_bytes());
        }
        payload.extend(0u64.to_le_bytes());
        put(&mut payload, index * 20, ilt)?;
        put(&mut payload, index * 20 + 12, dll)?;
        put(&mut payload, index * 20 + 16, group[0].iat_rva)?;
        patches.insert(group.last().unwrap().iat_rva + 8, 0);
    }
    ensure!(
        u32_at(ctx, layout.entry)? == 0,
        "unsupported x64 original entry mode"
    );
    let entry = u32_at(ctx, layout.entry + 8)?;
    ensure!(
        entry < host_end
            && pe.section_at(entry).is_some_and(|s| config
                .descriptors
                .iter()
                .any(|d| d.rva == s.rva && d.characteristics & 0x20000000 != 0)),
        "x64 original entry outside host code"
    );
    let runtime = Runtime::parse(loader)?;
    let roots: Vec<_> = runtime
        .streams
        .iter()
        .filter(|s| s.0 < host_end)
        .map(|s| s.0)
        .collect();
    let mut entry_patches = Vec::new();
    for root in roots {
        ensure!(
            root >= entry && root - entry <= 32,
            "x64 VM root outside startup prologue"
        );
        let call = imports::recovered_read(recovered, root, 5)?;
        let i = Decoder::with_ip(64, call, root as u64, DecoderOptions::NONE).decode();
        ensure!(
            i.mnemonic() == Mnemonic::Call
                && i.op0_kind() == OpKind::NearBranch64
                && i.near_branch64() >= engine.rva as u64,
            "x64 VM root has no runtime call"
        );
        let code = crate::devirt::x64::startup(loader, pe.image_base, host_end, root, root)?;
        entry_patches.push(Recovered {
            rva: root,
            bytes: code,
        });
    }
    let directory = pe.optional + 112;
    let exception_rva = u32_at(pe.data, directory + 24)?;
    let exception_size = u32_at(pe.data, directory + 28)? as usize;
    ensure!(
        exception_size.is_multiple_of(12),
        "invalid x64 exception directory length"
    );
    let mut exception = Vec::new();
    let mut previous = 0;
    for raw in pe.read(exception_rva, exception_size)?.as_chunks::<12>().0 {
        let start = u32_at(raw, 0)?;
        let end = u32_at(raw, 4)?;
        let unwind = u32_at(raw, 8)?;
        if start >= host_end {
            continue;
        }
        ensure!(
            start >= previous && start < end && end <= host_end && unwind < host_end,
            "invalid host x64 runtime function"
        );
        ensure!(
            pe.section_at(start).is_some_and(|s| config
                .descriptors
                .iter()
                .any(|d| d.rva == s.rva && d.characteristics & 0x20000000 != 0)),
            "x64 runtime function outside code"
        );
        imports::recovered_read(recovered, unwind, 4)?;
        previous = end;
        exception.extend(raw);
    }
    ensure!(!exception.is_empty(), "no x64 host exception entries");
    for patch in &entry_patches {
        ensure!(
            exception
                .as_chunks::<12>()
                .0
                .iter()
                .any(|r| u32_at(r, 0).unwrap() <= patch.rva
                    && patch.rva + patch.bytes.len() as u32 <= u32_at(r, 4).unwrap()),
            "native x64 entry exceeds its unwind function extent"
        );
    }
    let exception_size = exception.len();
    let pdata: Vec<_> = config
        .descriptors
        .iter()
        .filter(|d| {
            d.enabled
                && d.packed_size == 0
                && d.characteristics == 0x40000040
                && d.expanded_size == exception_size.next_multiple_of(pe.file_alignment as usize)
        })
        .collect();
    ensure!(
        pdata.len() == 1,
        "cannot identify original x64 exception section"
    );
    let exception_rva = pdata[0].rva;
    entry_patches.push(Recovered {
        rva: exception_rva,
        bytes: exception,
    });
    let original_index = u64_at(ctx, layout.tls)?;
    let mut tls_rva = 0;
    let mut fixups = Vec::new();
    if original_index != 0 {
        let index = u32::try_from(original_index)?;
        ensure!(
            pe.section_at(index).is_some_and(|s| config
                .descriptors
                .iter()
                .any(|d| d.rva == s.rva && d.characteristics & 0x80000000 != 0)),
            "x64 TLS index outside writable host"
        );
        let source = u32_at(pe.data, directory + 72)?;
        ensure!(
            u32_at(pe.data, directory + 76)? == 40,
            "invalid protected x64 TLS directory"
        );
        let raw = pe.read(source, 40)?;
        let to_rva = |va: u64| {
            u32::try_from(
                va.checked_sub(pe.image_base)
                    .context("x64 TLS address below image")?,
            )
            .context("x64 TLS address overflow")
        };
        ensure!(
            to_rva(u64_at(raw, 16)?)? as u64 == u64_at(ctx, layout.tls + 8)?,
            "x64 TLS index context mismatch"
        );
        let start = u64_at(raw, 0)?;
        let length = usize::try_from(
            u64_at(raw, 8)?
                .checked_sub(start)
                .context("x64 TLS template range")?,
        )?;
        ensure!(
            length <= codec::MAX_EXPANDED
                && u32_at(raw, 32)? as usize <= codec::MAX_EXPANDED - length,
            "oversized x64 TLS template"
        );
        let template = pe.read(to_rva(start)?, length)?;
        let mut callbacks = Vec::new();
        let callbacks_va = u64_at(raw, 24)?;
        if callbacks_va != 0 {
            let mut rva = to_rva(callbacks_va)?;
            loop {
                let value = u64_at(pe.read(rva, 8)?, 0)?;
                if value == 0 {
                    break;
                }
                ensure!(
                    to_rva(value)? < host_end,
                    "x64 TLS callback remains in runtime"
                );
                callbacks.push(value);
                ensure!(callbacks.len() <= 1024, "too many TLS callbacks");
                rva += 8;
            }
        }
        payload.resize(align(payload.len(), 8)?, 0);
        let at = payload.len();
        tls_rva = section_rva + u32::try_from(at)?;
        payload.extend(raw);
        let callbacks_rva = section_rva + u32::try_from(payload.len())?;
        for value in callbacks {
            fixups.push(section_rva + u32::try_from(payload.len())?);
            payload.extend(value.to_le_bytes());
        }
        payload.extend(0u64.to_le_bytes());
        let tls_align = (u32_at(raw, 36)? >> 20) & 15;
        let tls_align = if tls_align == 0 {
            8
        } else {
            1usize << (tls_align - 1)
        };
        payload.resize(align(payload.len(), tls_align)?, 0);
        let template_rva = section_rva + u32::try_from(payload.len())?;
        payload.extend(template);
        for (offset, rva) in [
            (0, template_rva),
            (8, template_rva + u32::try_from(length)?),
            (16, index),
            (24, callbacks_rva),
        ] {
            put64(&mut payload, at + offset, pe.image_base + rva as u64)?;
            fixups.push(tls_rva + offset as u32);
        }
    }
    let relocation_size = u32_at(ctx, layout.relocations + 4)? as usize;
    let mut relocs = Vec::new();
    if relocation_size != 0 {
        let rva = u32_at(ctx, layout.data)?
            .checked_add(u32_at(ctx, layout.relocations)?)
            .context("x64 relocation source overflow")?;
        relocs = codec::decompress(
            pe.read(rva, relocation_size)?,
            codec::expanded_size(u32_at(ctx, layout.relocations + 8)? as usize)?,
            true,
        )?;
        let mut at = 0;
        while at < relocs.len() {
            let page = u32_at(&relocs, at)?;
            let size = u32_at(&relocs, at + 4)? as usize;
            ensure!(
                size >= 8 && size.is_multiple_of(2),
                "invalid x64 relocation block"
            );
            take(&relocs, at, size)?;
            for offset in (at + 8..at + size).step_by(2) {
                let v = u16_at(&relocs, offset)?;
                ensure!(
                    v >> 12 == 0
                        || (v >> 12 == 10
                            && page as u64 + (v & 4095) as u64 + 8 <= host_end as u64),
                    "invalid x64 relocation target"
                );
            }
            at += size;
        }
        let mut pages = BTreeMap::<u32, Vec<u16>>::new();
        for rva in fixups {
            pages
                .entry(rva & !4095)
                .or_default()
                .push(0xa000 | (rva & 4095) as u16);
        }
        for (page, mut entries) in pages {
            if !entries.len().is_multiple_of(2) {
                entries.push(0);
            }
            relocs.extend(page.to_le_bytes());
            relocs.extend((8 + entries.len() as u32 * 2).to_le_bytes());
            for v in entries {
                relocs.extend(v.to_le_bytes());
            }
        }
    }
    payload.resize(align(payload.len(), 4)?, 0);
    let reloc_rva = section_rva + u32::try_from(payload.len())?;
    payload.extend(&relocs);
    let table = pe.optional + u16_at(pe.data, pe.nt + 20)? as usize;
    let count = host.len() + 1;
    ensure!(
        table + count * 40 <= pe.headers_size as usize,
        "insufficient x64 section header space"
    );
    let mut output = take(pe.data, 0, pe.headers_size as usize)?.to_vec();
    output[table..].fill(0);
    let mut code_size = 0u32;
    let mut data_size = 0u32;
    for (index, section) in host.iter().enumerate() {
        let mut bytes = if let Some(s) = recovered.iter().find(|s| s.rva == section.rva) {
            s.bytes.clone()
        } else if section.raw_size != 0 {
            pe.read(section.rva, section.raw_size as usize)?.to_vec()
        } else {
            Vec::new()
        };
        for (&rva, &value) in &patches {
            if rva >= section.rva && (rva - section.rva) as usize + 8 <= bytes.len() {
                put64(&mut bytes, (rva - section.rva) as usize, value)?;
            }
        }
        for patch in &entry_patches {
            if patch.rva >= section.rva && ((patch.rva - section.rva) as usize) < bytes.len() {
                let at = (patch.rva - section.rva) as usize;
                take(&bytes, at, patch.bytes.len())?;
                bytes[at..at + patch.bytes.len()].copy_from_slice(&patch.bytes);
            }
        }
        let flags = config
            .descriptors
            .iter()
            .find(|d| d.rva == section.rva)
            .map_or(section.characteristics, |d| d.characteristics);
        let at = table + index * 40;
        output[at..at + 40].copy_from_slice(take(pe.data, section.header_offset, 40)?);
        put(&mut output, at + 36, flags)?;
        let offset = align(output.len(), pe.file_alignment as usize)?;
        let raw = align(bytes.len(), pe.file_alignment as usize)?;
        ensure!(
            offset + raw <= codec::MAX_EXPANDED,
            "rebuilt x64 image too large"
        );
        output.resize(offset + raw, 0);
        output[offset..offset + bytes.len()].copy_from_slice(&bytes);
        put(
            &mut output,
            at + 8,
            section.virtual_size.max(u32::try_from(bytes.len())?),
        )?;
        put(&mut output, at + 16, u32::try_from(raw)?)?;
        put(
            &mut output,
            at + 20,
            if raw == 0 { 0 } else { u32::try_from(offset)? },
        )?;
        if flags & 0x20 != 0 {
            code_size += raw as u32;
        } else {
            data_size += raw as u32;
        }
    }
    let raw = align(payload.len(), pe.file_alignment as usize)?;
    let offset = align(output.len(), pe.file_alignment as usize)?;
    output.resize(offset + raw, 0);
    output[offset..offset + payload.len()].copy_from_slice(&payload);
    let at = table + host.len() * 40;
    output[at..at + 8].copy_from_slice(b".unpack\0");
    for (off, value) in [
        (8, payload.len() as u32),
        (12, section_rva),
        (16, raw as u32),
        (20, offset as u32),
        (36, 0x40000040),
    ] {
        put(&mut output, at + off, value)?;
    }
    output[pe.nt + 6..pe.nt + 8].copy_from_slice(&(count as u16).to_le_bytes());
    let flags = u16_at(&output, pe.nt + 22)?;
    let flags = if relocs.is_empty() {
        flags | 1
    } else {
        flags & !1
    };
    output[pe.nt + 22..pe.nt + 24].copy_from_slice(&flags.to_le_bytes());
    put(&mut output, pe.optional + 4, code_size)?;
    put(&mut output, pe.optional + 8, data_size + raw as u32)?;
    put(&mut output, pe.optional + 12, 0)?;
    put(&mut output, pe.optional + 16, entry)?;
    put(
        &mut output,
        pe.optional + 56,
        u32::try_from(align(
            section_rva as usize + payload.len(),
            section_alignment,
        )?)?,
    )?;
    let flags =
        u16_at(&output, pe.optional + 70)? & if relocs.is_empty() { !0x4060 } else { !0x4000 };
    output[pe.optional + 70..pe.optional + 72].copy_from_slice(&flags.to_le_bytes());
    let n = u32_at(pe.data, pe.optional + 108)? as usize;
    ensure!(
        n >= 13 && directory + n * 8 <= table,
        "missing x64 data directories"
    );
    output[directory..directory + n * 8].fill(0);
    for (index, rva, size) in [
        (1, section_rva, descriptors as u32),
        (
            2,
            u32_at(pe.data, directory + 16)?,
            u32_at(pe.data, directory + 20)?,
        ),
        (3, exception_rva, exception_size as u32),
        (
            5,
            if relocs.is_empty() { 0 } else { reloc_rva },
            relocs.len() as u32,
        ),
        (9, tls_rva, if tls_rva == 0 { 0 } else { 40 }),
        (
            12,
            *patches.first_key_value().unwrap().0,
            *patches.last_key_value().unwrap().0 - *patches.first_key_value().unwrap().0 + 8,
        ),
    ] {
        put(&mut output, directory + index * 8, rva)?;
        put(&mut output, directory + index * 8 + 4, size)?;
    }
    put(&mut output, pe.optional + 64, 0)?;
    let sum = checksum(&output, pe.optional + 64);
    put(&mut output, pe.optional + 64, sum)?;
    eprintln!(
        "Rebuilt x64 OEP {entry:#x}, {} imports, {} runtime functions",
        symbols.len(),
        exception_size / 12
    );
    Ok(output)
}
