//! Recognize the runtime's TLS-index restoration and PE relocation consumers.
use super::vm::BASE;
use crate::common::{
    io::{take, u32_at},
    pe::Pe,
};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic as M, OpKind, Register as R};
use std::{collections::HashSet, ops::Range};

fn memory(i: &Instruction, n: u32, base: R, offset: u32) -> bool {
    i.op_kind(n) == OpKind::Memory
        && i.memory_base() == base
        && i.memory_index() == R::None
        && i.memory_displacement32() == offset
}
fn literal(i: &Instruction, n: u32, value: u32) -> bool {
    matches!(
        i.op_kind(n),
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate8to32
    ) && i.immediate(n) as u32 == value
}
fn load(i: &Instruction, dest: R, base: R, offset: u32) -> bool {
    i.mnemonic() == M::Mov && i.op0_register() == dest && memory(i, 1, base, offset)
}
fn add(i: &Instruction, dest: R, base: R, offset: u32) -> bool {
    i.mnemonic() == M::Add && i.op0_register() == dest && memory(i, 1, base, offset)
}
fn body(image: &[u8], at: usize, limit: usize) -> Option<Vec<Instruction>> {
    let mut instructions = Vec::new();
    for i in Decoder::with_ip(
        32,
        image.get(at..)?,
        BASE as u64 + at as u64,
        DecoderOptions::NONE,
    )
    .into_iter()
    .take(limit)
    {
        if i.is_invalid() {
            return None;
        }
        instructions.push(i);
        if i.mnemonic() == M::Ret {
            return Some(instructions);
        }
    }
    None
}
fn virtual_protect_slots(image: &[u8], pe: &Pe<'_>) -> Result<HashSet<u32>> {
    let mut slots = HashSet::new();
    let mut descriptor = u32_at(image, pe.optional + 104)? as usize;
    ensure!(descriptor != 0, "Loader has no import directory");
    for _ in 0..1024 {
        let iat = u32_at(image, descriptor + 16)?;
        if iat == 0 {
            return Ok(slots);
        }
        let names = u32_at(image, descriptor)?;
        let names = if names == 0 { iat } else { names };
        for index in 0..65536 {
            let name = u32_at(image, names as usize + index * 4)?;
            if name == 0 {
                break;
            }
            if name & 0x80000000 == 0
                && image.get(name as usize + 2..name as usize + 17)
                    == Some(b"VirtualProtect\0".as_slice())
            {
                slots.insert(
                    BASE.checked_add(iat)
                        .and_then(|at| at.checked_add(index as u32 * 4))
                        .context("Loader IAT address overflow")?,
                );
            }
        }
        descriptor += 20;
    }
    anyhow::bail!("unterminated Loader import directory")
}
fn is_virtual_protect(image: &[u8], mut target: u32, slots: &HashSet<u32>) -> bool {
    for _ in 0..8 {
        let Some(at) = target.checked_sub(BASE) else {
            return false;
        };
        let Some(code) = image.get(at as usize..) else {
            return false;
        };
        let i = Decoder::with_ip(32, code, target as u64, DecoderOptions::NONE).decode();
        if i.mnemonic() != M::Jmp {
            return false;
        }
        if i.op0_kind() == OpKind::NearBranch32 {
            target = i.near_branch32();
            continue;
        }
        if i.op0_kind() != OpKind::Memory
            || i.memory_base() != R::None
            || i.memory_index() != R::None
        {
            return false;
        }
        let slot = i.memory_displacement32();
        if slots.contains(&slot) {
            return true;
        }
        let Some(at) = slot.checked_sub(BASE) else {
            return false;
        };
        let Ok(value) = u32_at(image, at as usize) else {
            return false;
        };
        target = value;
    }
    false
}
fn tls(image: &[u8], at: usize, fields: &Range<usize>, protect: &HashSet<u32>) -> Option<usize> {
    let prefix = Decoder::with_ip(
        32,
        image.get(at..)?,
        BASE as u64 + at as u64,
        DecoderOptions::NONE,
    )
    .into_iter()
    .take(7)
    .collect::<Vec<_>>();
    let [push, stack, self_reg, first, skip, second, skip2] = prefix.as_slice() else {
        return None;
    };
    let offset = first.memory_displacement32();
    if push.mnemonic() != M::Push
        || push.op0_register() != R::EBX
        || stack.mnemonic() != M::Add
        || stack.op0_register() != R::ESP
        || !literal(stack, 1, (-8i32) as u32)
        || self_reg.mnemonic() != M::Mov
        || self_reg.op0_register() != R::EBX
        || self_reg.op1_register() != R::EAX
        || first.mnemonic() != M::Cmp
        || first.memory_size().size() != 4
        || !memory(first, 0, R::EBX, offset)
        || !literal(first, 1, 0)
        || !fields.contains(&(offset as usize))
        || offset as usize + 8 > fields.end
        || second.mnemonic() != M::Cmp
        || second.memory_size().size() != 4
        || !memory(second, 0, R::EBX, offset + 4)
        || !literal(second, 1, 0)
        || skip.mnemonic() != M::Je
        || skip2.mnemonic() != M::Je
        || skip.near_branch_target() != skip2.near_branch_target()
    {
        return None;
    }
    let instructions = body(image, at, 96)?;
    let calls = instructions
        .iter()
        .filter(|i| i.mnemonic() == M::Call)
        .collect::<Vec<_>>();
    if calls.len() != 4
        || !calls.iter().all(|i| {
            i.op0_kind() == OpKind::NearBranch32
                && is_virtual_protect(image, i.near_branch32(), protect)
        })
    {
        return None;
    }
    let copies = instructions
        .windows(6)
        .filter(|w| {
            let base = w[0].memory_displacement32();
            load(&w[0], R::EAX, R::EBX, base)
                && base < (fields.start as u32)
                && w[1].mnemonic() == M::Mov
                && w[1].op0_register() == R::EDX
                && w[1].op1_register() == R::EAX
                && add(&w[2], R::EDX, R::EBX, offset + 4)
                && load(&w[3], R::EDX, R::EDX, 0)
                && add(&w[4], R::EAX, R::EBX, offset)
                && w[5].mnemonic() == M::Mov
                && memory(&w[5], 0, R::EAX, 0)
                && w[5].op1_register() == R::EDX
        })
        .count();
    (copies == 1).then_some(offset as usize)
}
fn highlow(image: &[u8], address: u32) -> bool {
    let Some(at) = address.checked_sub(BASE) else {
        return false;
    };
    let Some(code) = body(image, at as usize, 128) else {
        return false;
    };
    let entries = code.iter().any(|i| {
        i.mnemonic() == M::Mov
            && i.op0_register() == R::BX
            && i.op1_kind() == OpKind::Memory
            && i.memory_index_scale() == 2
            && i.memory_displacement32() == 8
    });
    let offset = code
        .iter()
        .any(|i| i.mnemonic() == M::And && i.op0_register() == R::BX && literal(i, 1, 0xfff));
    let kind = code.windows(3).any(|w| {
        w[0].mnemonic() == M::Shr
            && w[0].op0_register() == R::EBX
            && literal(&w[0], 1, 12)
            && w[1].mnemonic() == M::And
            && w[1].op0_register() == R::EBX
            && literal(&w[1], 1, 15)
            && w[2].mnemonic() == M::Sub
            && w[2].op0_register() == R::EBX
            && literal(&w[2], 1, 3)
    });
    let fixup = code
        .iter()
        .any(|i| i.mnemonic() == M::Add && memory(i, 0, R::ESI, 0) && i.op1_register() == R::EBX);
    entries && offset && kind && fixup
}
fn relocations(image: &[u8], at: usize, data: &Range<usize>) -> Option<usize> {
    let prefix = Decoder::with_ip(
        32,
        image.get(at..)?,
        BASE as u64 + at as u64,
        DecoderOptions::NONE,
    )
    .into_iter()
    .take(8)
    .collect::<Vec<_>>();
    let [push, save, global, self_reg, packed, skip, reload, expanded] = prefix.as_slice() else {
        return None;
    };
    let field = packed.memory_displacement32().checked_sub(4)?;
    if !data.contains(&(field as usize)) || field as usize + 12 > data.end {
        return None;
    }
    if push.mnemonic() != M::Push
        || push.op0_register() != R::EBX
        || save.mnemonic() != M::Push
        || save.op0_register() != R::ESI
        || global.mnemonic() != M::Mov
        || global.op0_register() != R::ESI
        || global.op1_kind() != OpKind::Memory
        || global.memory_base() != R::None
        || !load(self_reg, R::EAX, R::ESI, 0)
        || !load(reload, R::EAX, R::ESI, 0)
        || packed.mnemonic() != M::Cmp
        || packed.memory_size().size() != 4
        || !memory(packed, 0, R::EAX, field + 4)
        || !literal(packed, 1, 0)
        || skip.mnemonic() != M::Je
        || !load(expanded, R::EAX, R::EAX, field + 8)
    {
        return None;
    }
    let instructions = body(image, at, 64)?;
    let source = instructions.windows(5).any(|w| {
        load(&w[0], R::EAX, R::EAX, field)
            && load(&w[1], R::EDX, R::ESI, 0)
            && add(&w[2], R::EAX, R::EDX, data.start as u32)
            && load(&w[3], R::EDX, R::ESI, 0)
            && add(&w[4], R::EAX, R::EDX, w[4].memory_displacement32())
            && (w[4].memory_displacement32() as usize) < data.start
    });
    let apply = instructions
        .iter()
        .rev()
        .find(|i| i.mnemonic() == M::Call)?;
    (source && apply.op0_kind() == OpKind::NearBranch32 && highlow(image, apply.near_branch32()))
        .then_some(field as usize)
}
pub(super) fn derive(
    image: &[u8],
    data: Range<usize>,
    entry: Range<usize>,
) -> Result<(usize, usize)> {
    let pe = Pe::parse(image)?;
    let protect = virtual_protect_slots(image, &pe)?;
    ensure!(!protect.is_empty(), "Loader does not import VirtualProtect");
    let mut tls_fields = Vec::new();
    let mut reloc_fields = Vec::new();
    for section in pe
        .sections
        .iter()
        .filter(|s| s.characteristics & 0x20000000 != 0)
    {
        let bytes = take(image, section.rva as usize, section.virtual_size as usize)?;
        for (offset, &first) in bytes.iter().enumerate() {
            if first != 0x53 {
                continue;
            }
            let at = section.rva as usize + offset;
            match bytes.get(offset + 1) {
                Some(0x83) => {
                    if let Some(field) = tls(image, at, &entry, &protect) {
                        tls_fields.push(field);
                    }
                }
                Some(0x56) => {
                    if let Some(field) = relocations(image, at, &data) {
                        reloc_fields.push(field);
                    }
                }
                _ => {}
            }
        }
    }
    tls_fields.sort_unstable();
    tls_fields.dedup();
    reloc_fields.sort_unstable();
    reloc_fields.dedup();
    ensure!(
        tls_fields.len() == 1,
        "cannot uniquely derive TLS index transfer: {tls_fields:x?}"
    );
    ensure!(
        reloc_fields.len() == 1,
        "cannot uniquely derive HIGHLOW relocation consumer: {reloc_fields:x?}"
    );
    Ok((tls_fields[0], reloc_fields[0]))
}
