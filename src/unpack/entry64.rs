//! Reached x64 bootstrap instructions; counted XOR and LZ calls are summarized.
use super::entry::Entry;
use crate::{
    common::{
        codec,
        io::{take, u32_at, u64_at},
        pe::Pe,
    },
    devirt::static_x64::{self as cpu, Image, State, Value},
};
use anyhow::{Context, Result, bail, ensure};
use iced_x86::{Mnemonic as M, OpKind, Register as R};

pub(super) fn parse(pe: &Pe<'_>) -> Result<Entry> {
    let base = pe.image_base;
    let mut image = Image::default();
    image.add(base, take(pe.data, 0, pe.headers_size as usize)?.to_vec())?;
    for s in &pe.sections {
        if s.raw_size != 0 {
            image.add(
                base + s.rva as u64,
                take(pe.data, s.raw_offset as usize, s.raw_size as usize)?.to_vec(),
            )?;
        }
    }
    let mut imports = std::collections::HashMap::new();
    let mut desc = u32_at(pe.data, pe.optional + 120)?;
    if desc != 0 {
        for _ in 0..1024 {
            let d = pe.read(desc, 20)?;
            if d == [0; 20] {
                break;
            }
            let iat = u32_at(d, 16)?;
            let lookup = u32_at(d, 0)?;
            let lookup = if lookup == 0 { iat } else { lookup };
            for index in 0..65536 {
                let v = u64_at(pe.read(lookup + index * 8, 8)?, 0)?;
                if v == 0 {
                    break;
                }
                if v >> 63 == 0 {
                    let mut name = Vec::new();
                    for n in 0..256 {
                        let b = pe.read(u32::try_from(v)? + 2 + n, 1)?[0];
                        if b == 0 {
                            break;
                        }
                        name.push(b);
                    }
                    imports.insert(
                        base + iat as u64 + index as u64 * 8,
                        String::from_utf8(name)?,
                    );
                }
            }
            desc = desc.checked_add(20).context("x64 import RVA overflow")?;
        }
    }
    let mut state = State::new(base + pe.entry as u64, 0x200100000);
    let mut loader = None;
    let mut loader_entry = None;
    let mut packed: Option<(u64, Vec<u8>)> = None;
    for _ in 0..2_000_000 {
        if Some(state.pc) == loader_entry {
            return Ok(Entry {
                loader,
                metadata: u32::try_from(
                    cpu::reg(&state, R::R8)?.require("x64 metadata argument")?,
                )?,
            });
        }
        let i = image.instruction(state.pc)?;
        if i.mnemonic() == M::Ret && loader.is_none() && packed.is_none() {
            return Ok(Entry {
                loader: None,
                metadata: u32::try_from(
                    cpu::reg(&state, R::R8)?.require("x64 metadata argument")?,
                )?,
            });
        }
        if i.mnemonic() == M::Stmxcsr {
            state.pc = i.next_ip();
            continue;
        }
        if i.mnemonic() == M::Xor && i.op0_kind() == OpKind::Memory {
            let address = cpu::address(&state, &i)?.require("x64 XOR address")?;
            let width = i.memory_size().size();
            ensure!(matches!(width, 1 | 4), "unsupported x64 XOR width");
            let key = cpu::operand(&state, &image, &i, 1)?.require("x64 XOR key")?;
            let inc = image.instruction(i.next_ip())?;
            let dec = image.instruction(inc.next_ip())?;
            let branch = image.instruction(dec.next_ip())?;
            let pointer = i.memory_base();
            let counter = dec.op0_register();
            ensure!(
                i.memory_index() == R::None
                    && i.memory_displacement64() == 0
                    && pointer != counter
                    && i.op1_kind() == OpKind::Register
                    && i.op1_register().full_register() != pointer
                    && i.op1_register().full_register() != counter
                    && pointer.size() == 8
                    && counter.size() == 8
                    && inc.op0_register() == pointer
                    && ((inc.mnemonic() == M::Inc && width == 1)
                        || (inc.mnemonic() == M::Add && inc.immediate(1) == width as u64))
                    && dec.mnemonic() == M::Dec
                    && branch.mnemonic() == M::Jne
                    && branch.near_branch64() == i.ip(),
                "unsupported x64 counted XOR loop"
            );
            let count = cpu::reg(&state, counter)?.require("x64 XOR count")?;
            let length = codec::expanded_size(usize::try_from(
                count
                    .checked_mul(width as u64)
                    .context("x64 XOR size overflow")?,
            )?)?;
            let mut bytes = Vec::with_capacity(length);
            for n in 0..length {
                bytes.push(
                    state
                        .read(&image, address + n as u64, 1)
                        .require("x64 XOR source")? as u8
                        ^ (key >> ((n % width) * 8)) as u8,
                );
            }
            cpu::set_reg(
                &mut state,
                pointer,
                Value::constant(address + length as u64),
            )?;
            cpu::set_reg(&mut state, counter, Value::constant(1))?;
            cpu::execute(&mut state, &image, &dec)?;
            state.pc = branch.next_ip();
            image.patch(address, &bytes)?;
            if width == 4 {
                ensure!(packed.is_none(), "multiple x64 packed runtimes");
                packed = Some((address, bytes));
            }
            continue;
        }
        if i.mnemonic() == M::Call {
            if let Some((source, bytes)) = &packed
                && loader.is_none()
                && cpu::reg(&state, R::RCX)?.get() == Some(*source)
                && cpu::reg(&state, R::RAX)?
                    .get()
                    .is_some_and(|n| n >= bytes.len() as u64 && n < bytes.len() as u64 + 4)
            {
                let dest = cpu::reg(&state, R::RDX)?.require("x64 runtime destination")?;
                let rva = u32::try_from(dest.checked_sub(base).context("runtime below host")?)?;
                let section = pe
                    .section_at(rva)
                    .context("runtime destination outside image")?;
                ensure!(
                    section.rva == rva,
                    "runtime destination is not section start"
                );
                let mut stream = bytes.clone();
                let length = cpu::reg(&state, R::RAX)?.get().unwrap() as usize;
                stream.extend(pe.read(
                    u32::try_from(source - base)? + bytes.len() as u32,
                    length - bytes.len(),
                )?);
                let mut decoded = codec::decompress(&stream, section.virtual_size as usize, false)?;
                codec::fix_branches(&mut decoded);
                let dll = Pe::parse(&decoded)?;
                ensure!(dll.is_64, "x64 bootstrap decoded another architecture");
                loader_entry = Some(dest + dll.entry as u64);
                image.replace_region(dest, decoded.clone())?;
                loader = Some(decoded);
                state.pc = i.next_ip();
                continue;
            }
            if i.op0_kind() == OpKind::Memory {
                let slot = cpu::address(&state, &i)?.require("x64 API slot")?;
                let name = imports.get(&slot).context("unknown x64 bootstrap API")?;
                ensure!(
                    matches!(
                        name.as_str(),
                        "LoadLibraryA" | "GetProcAddress" | "GetModuleHandleA"
                    ),
                    "unsupported x64 bootstrap API {name}"
                );
                state.registers[0] = Value::constant(0x700000000);
                state.flags = Value::unknown_flags();
                state.pc = i.next_ip();
                continue;
            }
        }
        ensure!(
            cpu::execute(&mut state, &image, &i)
                .with_context(|| format!("x64 bootstrap at {:#x} {:?}", i.ip(), i.mnemonic()))?
                .is_none(),
            "x64 bootstrap depends on unknown input"
        );
    }
    bail!("x64 bootstrap instruction limit")
}
