//! Recover the Loader's entry references and serialized configuration projection.
use super::{
    static_x86::{Image, Value},
    vm::{BASE, Tokens},
};
use crate::common::io::{take, u32_at};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Mnemonic as M, OpKind, Register};

#[cfg(test)]
#[path = "../../test/loader.rs"]
mod tests;

pub(super) struct Bootstrap {
    pub header: usize,
    pub dispatch: u32,
    pub trampoline: u32,
}

pub(crate) struct ImportFields {
    pub descriptor: usize,
    pub name_key: usize,
    pub license_key: Option<usize>,
    pub flag_size: usize,
}

impl Bootstrap {
    pub fn parse(image: &[u8]) -> Result<Self> {
        let entry = u32_at(image, u32_at(image, 0x3c)? as usize + 40)? as usize;
        let mut decoder = Decoder::with_ip(
            32,
            take(image, entry, 40)?,
            BASE as u64 + entry as u64,
            DecoderOptions::NONE,
        );
        let first = decoder.decode();
        ensure!(
            first.mnemonic() == M::Push && first.op0_kind() == OpKind::Immediate32,
            "Loader entry does not pass a token header"
        );
        let header = first.immediate32() as usize;
        for _ in 0..2 {
            let i = decoder.decode();
            ensure!(
                i.mnemonic() == M::Push && i.op0_kind() == OpKind::Memory,
                "unsupported Loader initializer argument"
            );
        }
        let initializer = decoder.decode();
        ensure!(
            initializer.mnemonic() == M::Call && initializer.op0_kind() == OpKind::NearBranch32,
            "missing Loader initializer call"
        );
        let startup = decoder
            .into_iter()
            .find(|i| i.mnemonic() == M::Call && i.op0_kind() == OpKind::NearBranch32)
            .context("missing Loader startup call")?
            .near_branch32();
        let at = startup
            .checked_sub(BASE)
            .context("Loader startup below base")? as usize;
        let mut decoder = Decoder::with_ip(
            32,
            take(image, at, 128)?,
            startup as u64,
            DecoderOptions::NONE,
        );
        let mut references = None;
        while decoder.can_decode() {
            let branch = decoder.decode();
            if branch.mnemonic() != M::Jmp
                || branch.op0_kind() != OpKind::NearBranch32
                || branch.near_branch32() <= branch.next_ip32()
            {
                continue;
            }
            let mut anchors = Vec::new();
            while decoder.ip() < branch.near_branch_target() {
                let i = decoder.decode();
                ensure!(
                    !i.is_invalid() && decoder.ip() <= branch.near_branch_target(),
                    "invalid Loader startup reference block"
                );
                anchors.push(i);
            }
            if anchors.len() == 3
                && anchors
                    .iter()
                    .all(|i| i.mnemonic() == M::Call && i.op0_kind() == OpKind::NearBranch32)
                && anchors[0].near_branch32() == initializer.near_branch32()
            {
                references = Some((anchors[1].near_branch32(), anchors[2].near_branch32()));
                break;
            }
        }
        let (dispatch, trampoline) =
            references.context("Loader startup has no interpreter references")?;
        let dispatch = dispatch
            .checked_sub(BASE)
            .context("dispatcher below base")?;
        let trampoline = trampoline
            .checked_sub(BASE)
            .context("trampoline below base")?;
        let mut d = Decoder::new(32, take(image, dispatch as usize, 2)?, DecoderOptions::NONE);
        ensure!(
            d.decode().mnemonic() == M::Pushad && d.decode().mnemonic() == M::Pushfd,
            "interpreter entry does not save the machine state"
        );
        let mut d = Decoder::new(
            32,
            take(image, trampoline as usize, 7)?,
            DecoderOptions::NONE,
        );
        let jump = d.decode();
        ensure!(
            jump.mnemonic() == M::Jmp
                && jump.op0_kind() == OpKind::Memory
                && jump.memory_base() == Register::None
                && jump.memory_index() == Register::None
                && d.decode().mnemonic() == M::Ret,
            "invalid template interpreter trampoline"
        );
        Ok(Self {
            header,
            dispatch,
            trampoline,
        })
    }
}

impl Tokens<'_> {
    /// Recover the older MD5-keyed, in-place four-byte IDEA entry consumer.
    /// Offsets come from its operands, including the hash source and check value.
    pub(super) fn entry_cipher(
        &self,
        data: usize,
        entry: usize,
        end: usize,
    ) -> Result<Option<super::vm::EntryCipher>> {
        let mut image = Image::default();
        image.add(BASE, self.image.to_vec())?;
        let mut found = None;
        let operand =
            |index: usize, op: u32, dest: u32, kind: u32, base: u32| -> Result<Option<u32>> {
                let raw = self.records[index];
                (u32_at(raw, 0)? == op
                    && u32_at(raw, 12)? == 0x8c
                    && u32_at(raw, 16)? == 0x25 + dest
                    && u32_at(raw, 32)? == kind
                    && u32_at(raw, 36)? == 0x25 + base)
                    .then(|| u32_at(raw, 48))
                    .transpose()
            };
        for call in 19..self.records.len().saturating_sub(10) {
            if operand(call - 5, 0x51, 2, 0x8d, 0)? != Some(entry as u32)
                || operand(call - 19, 0x4d, 0, 0x8d, 2)? != Some(data as u32)
                || self.native_call(call)?.is_none()
                || self.scalar(&mut image, call - 1, 1)? != Some(4)
                || self.register_offset(&mut image, call - 2, 0)? != Some(entry as u32)
            {
                continue;
            }
            let Some(offset) = operand(call - 16, 0x4d, 0, 0x8d, 2)? else {
                continue;
            };
            let Some(bias) = self.register_offset(&mut image, call - 15, 0)? else {
                continue;
            };
            let Some(local) = operand(call - 14, 0x51, 1, 0x8d, 5)? else {
                continue;
            };
            let Some(length) = operand(call - 11, 0x52, 2, 0x8d, 2)? else {
                continue;
            };
            let Some(digest) = operand(call + 6, 0x51, 2, 0x8d, 0)? else {
                continue;
            };
            let push = self.records[call - 8];
            if self.native_call(call - 10)?.is_none()
                || operand(call - 9, 0x51, 0, 0x8d, 5)? != Some(local)
                || u32_at(push, 0)? != 0x5a
                || u32_at(push, 12)? != 0x8c
                || u32_at(push, 16)? != 0x25
                || operand(call + 7, 0x51, 0, 0x8d, 5)? != Some(local)
                || self.scalar(&mut image, call + 8, 1)? != Some(16)
                || self.native_call(call + 9)?.is_none()
            {
                continue;
            }
            ensure!(
                offset as usize >= data
                    && offset as usize + 4 <= entry
                    && length as usize >= entry
                    && length as usize + 4 <= end
                    && digest as usize >= entry
                    && digest as usize + 16 <= end,
                "encrypted entry consumer references fields outside its configuration blocks"
            );
            ensure!(found.is_none(), "ambiguous encrypted entry consumer");
            found = Some(super::vm::EntryCipher {
                offset: offset as usize,
                bias,
                length: length as usize,
                digest: digest as usize,
            });
        }
        Ok(found)
    }

    pub(super) fn section_suffix(&self) -> Result<usize> {
        let mut image = Image::default();
        image.add(BASE, self.image.to_vec())?;
        let mut fields = Vec::new();
        for index in 2..self.records.len().saturating_sub(2) {
            let compare = self.records[index];
            let branch = self.records[index + 1];
            if u32_at(compare, 0)? != 0x50
                || u32_at(compare, 12)? != 0x8d
                || u32_at(compare, 16)? != 0x25
                || ((u32_at(compare, 24)? >> 8) & 255) != 8
                || u32_at(compare, 32)? != 0x8f
                || u32_at(compare, 48)? != 0
                || u32_at(branch, 0)? != 0x2c
                || (u32_at(self.records[index + 2], 0)? != 0x232
                    && self.native_call(index + 2)?.is_none())
            {
                continue;
            }
            let end = u32_at(branch, 28)? as usize;
            if end <= index + 8 || end > self.records.len() || end - index > 128 {
                continue;
            }
            for call in index + 8..end - 1 {
                let Some(target) = self.native_call(call)? else {
                    continue;
                };
                if !self.copy_function(target) || self.scalar(&mut image, call - 1, 1)? != Some(16)
                {
                    continue;
                }
                let digest = self.records[call - 8];
                let source = self.records[call - 4];
                if u32_at(digest, 0)? != 0x51
                    || u32_at(digest, 16)? != 0x26
                    || u32_at(digest, 32)? != 0x8d
                    || u32_at(digest, 36)? != 0x29
                    || u32_at(source, 0)? != 0x51
                    || u32_at(source, 16)? != 0x27
                    || u32_at(source, 32)? != 0x8d
                    || u32_at(source, 36)? != 0x29
                    || u32_at(digest, 48)? != u32_at(source, 48)?
                    || self.native_call(call - 5)?.is_none()
                {
                    continue;
                }
                let mut append = false;
                for cursor in [3, 6, 7] {
                    if self.register_offset(&mut image, call + 1, cursor)? != Some(16) {
                        continue;
                    }
                    let add = self.records[call - 2];
                    if u32_at(add, 0)? == 0x4d {
                        append = u32_at(add, 12)? == 0x8c
                            && u32_at(add, 16)? == 0x25
                            && u32_at(add, 32)? == 0x8c
                            && u32_at(add, 36)? == 0x25 + cursor as u32;
                    } else if u32_at(add, 0)? == 0x231 {
                        append = true;
                        for seed in [0x41000000u32, 0x57391820, 0x6b9e207c] {
                            let inputs = std::array::from_fn(|r| {
                                Value::constant(
                                    seed.wrapping_add((r as u32 + 1).wrapping_mul(0x10379)),
                                )
                            });
                            let output = self.extension_inputs(&mut image, call - 2, inputs)?;
                            append &= output[0].get()
                                == Some(
                                    inputs[0]
                                        .get()
                                        .unwrap()
                                        .wrapping_add(inputs[cursor].get().unwrap()),
                                )
                                && output[1..] == inputs[1..];
                        }
                    }
                    if append {
                        break;
                    }
                }
                if append {
                    ensure!(
                        self.source_memory(&mut image, index - 1)? == Some((0, 0, 4)),
                        "section key suffix guard does not use the Loader context"
                    );
                    fields.push(u32_at(compare, 28)? as usize);
                }
            }
        }
        fields.sort_unstable();
        fields.dedup();
        ensure!(
            fields.len() == 1,
            "cannot uniquely derive machine-dependent section key guard"
        );
        Ok(fields[0])
    }

    fn native_call(&self, index: usize) -> Result<Option<u32>> {
        let raw = self.records[index];
        (u32_at(raw, 0)? == 0x60 && u32_at(raw, 12)? == 0x90)
            .then(|| u32_at(raw, 28))
            .transpose()
    }

    fn source_memory(&self, image: &mut Image, index: usize) -> Result<Option<(usize, u32, u32)>> {
        let raw = self.records[index];
        if u32_at(raw, 0)? == 0x231 {
            return self.extension_access(image, index);
        }
        let register = u32_at(raw, 36)?;
        if u32_at(raw, 32)? != 0x8d
            || !(0x25..=0x2c).contains(&register)
            || u32_at(raw, 40)? != 0
            || u32_at(raw, 44)? & 1 != 0
        {
            return Ok(None);
        }
        Ok(Some((
            (register - 0x25) as usize,
            u32_at(raw, 48)?,
            ((u32_at(raw, 44)? >> 8) & 255) / 8,
        )))
    }

    pub(crate) fn import_fields(
        &self,
        data: usize,
        header_end: usize,
        ctx_size: usize,
    ) -> Result<ImportFields> {
        let mut image = Image::default();
        image.add(BASE, self.image.to_vec())?;
        let mut getters = Vec::new();
        for index in 0..self.records.len().saturating_sub(5) {
            let Some(target) = self.native_call(index)? else {
                continue;
            };
            let Some(code) = self.image.get(target as usize..).filter(|b| b.len() >= 8) else {
                continue;
            };
            let mut d = Decoder::new(32, code, DecoderOptions::NONE);
            let add = d.decode();
            if add.mnemonic() != M::Add
                || add.op0_register() != Register::EAX
                || !matches!(add.op1_kind(), OpKind::Immediate32 | OpKind::Immediate8to32)
                || d.decode().mnemonic() != M::Ret
            {
                continue;
            }
            let key = add.immediate(1) as u32;
            if key == 0 || key as usize + 16 > data {
                continue;
            }
            let push = self.records[index + 1];
            if u32_at(push, 0)? != 0x5a || u32_at(push, 12)? != 0x8c || u32_at(push, 16)? != 0x25 {
                continue;
            }
            let Some((0, field, 4)) = self.source_memory(&mut image, index + 4)? else {
                continue;
            };
            if (data..header_end.saturating_sub(11)).contains(&(field as usize)) {
                getters.push((index, key, field));
            }
        }
        ensure!(
            getters.len() == 1,
            "cannot uniquely derive import buffer consumer: {} getters",
            getters.len()
        );
        let (getter, key_offset, descriptor) = getters[0];
        let mut reads = Vec::new();
        let mut cipher = None;
        let mut parser = None;
        for index in getter + 1..(getter + 128).min(self.records.len()) {
            if cipher.is_none() {
                if let Some(read) = self.source_memory(&mut image, index)? {
                    reads.push(read);
                }
                if let Some(target) = self.native_call(index)? {
                    cipher = Some(target);
                }
            }
            if u32_at(self.records[index], 0)? == 0x232 {
                parser = Some(u32_at(self.records[index], 28)? as usize);
                break;
            }
            if let Some(target) = self.native_call(index)?
                && self.image.get(target as usize..).is_some_and(|code| {
                    Decoder::new(32, code, DecoderOptions::NONE)
                        .decode()
                        .mnemonic()
                        == M::Jmp
                })
                && let Ok(token) =
                    super::vm::stub_token_at(self.image, target, self.key, self.dispatch)
            {
                parser = Some(token as usize);
                break;
            }
        }
        ensure!(
            reads.contains(&(2, data as u32, 4)) && reads.contains(&(2, descriptor + 4, 4)),
            "import source and packed size do not use the recovered data block"
        );
        let cipher = cipher.context("import consumer has no decrypt call")?;
        let parser = parser.context("import consumer has no record parser")?;
        ensure!(
            parser < self.records.len(),
            "import parser token outside table"
        );
        let mut flag_size = None;
        let mut name_keys = Vec::new();
        for index in parser..(parser + 512).min(self.records.len()) {
            let raw = self.records[index];
            if u32_at(raw, 0)? == 0x61 {
                break;
            }
            if index >= 2
                && u32_at(raw, 0)? == 0x58
                && u32_at(raw, 12)? == 0x8d
                && u32_at(raw, 32)? == 0x8f
                && u32_at(raw, 48)? == 1
            {
                let advance = self.records[index - 1];
                let size = if u32_at(advance, 0)? == 2
                    && u32_at(advance, 12)? == 0x8c
                    && u32_at(advance, 16)? == 0x28
                {
                    Some(1)
                } else {
                    self.register_offset(&mut image, index - 1, 3)?
                };
                if let Some(size) = size.filter(|n| matches!(n, 1 | 4)) {
                    let save = self.records[index - 2];
                    ensure!(
                        u32_at(save, 0)? == 0x52
                            && u32_at(save, 12)? == 0x8d
                            && ((u32_at(save, 24)? >> 8) & 255) == size * 8,
                        "import flag width differs from stream advance"
                    );
                    flag_size = Some(size as usize);
                }
            }
            if self.native_call(index)? == Some(cipher) && index >= 8 {
                let offset = self
                    .register_offset(&mut image, index - 8, 2)?
                    .context("import name key is not a context address")?
                    as usize;
                ensure!(
                    offset + 17 <= ctx_size,
                    "import name key outside serialized context"
                );
                name_keys.push(offset + 1);
            }
        }
        name_keys.sort_unstable();
        name_keys.dedup();
        ensure!(
            name_keys.len() == 1,
            "cannot uniquely derive import name key"
        );
        let mut license_keys = Vec::new();
        for index in 5..self.records.len() {
            let Some(target) = self.native_call(index)? else {
                continue;
            };
            let Some(code) = self.image.get(target as usize..).filter(|b| b.len() >= 18) else {
                continue;
            };
            let mut d =
                Decoder::with_ip(32, code, BASE as u64 + target as u64, DecoderOptions::NONE);
            let push = d.decode();
            let zero = d.decode();
            let load = d.decode();
            let xor = d.decode();
            let inc = d.decode();
            let cmp = d.decode();
            let back = d.decode();
            let pop = d.decode();
            let ret = d.decode();
            if push.mnemonic() != M::Push
                || push.op0_register() != Register::EBX
                || zero.mnemonic() != M::Xor
                || zero.op0_register() != Register::ECX
                || zero.op1_register() != Register::ECX
                || load.mnemonic() != M::Mov
                || load.op0_register() != Register::EBX
                || load.op1_kind() != OpKind::Memory
                || load.memory_base() != Register::EDX
                || load.memory_index() != Register::ECX
                || load.memory_index_scale() != 4
                || load.memory_displacement32() != 0
                || xor.mnemonic() != M::Xor
                || xor.op0_kind() != OpKind::Memory
                || xor.op1_register() != Register::EBX
                || xor.memory_base() != Register::EAX
                || xor.memory_index() != Register::ECX
                || xor.memory_index_scale() != 4
                || xor.memory_displacement32() != key_offset
                || inc.mnemonic() != M::Inc
                || inc.op0_register() != Register::ECX
                || cmp.mnemonic() != M::Cmp
                || cmp.op0_register() != Register::ECX
                || cmp.op1_kind() != OpKind::Immediate8to32
                || cmp.immediate8to32() != 4
                || back.mnemonic() != M::Jne
                || back.near_branch_target() != load.ip()
                || pop.mnemonic() != M::Pop
                || pop.op0_register() != Register::EBX
                || ret.mnemonic() != M::Ret
            {
                continue;
            }
            let address = self.records[index - 3];
            if !(u32_at(address, 0)? == 0x51
                && u32_at(address, 12)? == 0x8c
                && u32_at(address, 16)? == 0x27
                && u32_at(address, 32)? == 0x8d
                && u32_at(address, 36)? == 0x25)
            {
                continue;
            }
            let offset = u32_at(address, 48)? as usize;
            let before = self.records[index - 5];
            let reload = self.records[index - 2];
            if offset < header_end
                || u32_at(before, 0)? != 0x52
                || u32_at(reload, 0)? != 0x52
                || u32_at(before, 16)? != 0x25
                || u32_at(reload, 16)? != 0x25
                || u32_at(before, 32)? != 0x8d
                || u32_at(reload, 32)? != 0x8d
                || u32_at(before, 36)? != 0
                || u32_at(reload, 36)? != 0
                || u32_at(before, 48)? != u32_at(reload, 48)?
            {
                continue;
            }
            ensure!(
                self.source_memory(&mut image, index - 4)? == Some((0, 0, 4))
                    && self.source_memory(&mut image, index - 1)? == Some((0, 0, 4)),
                "license source and key buffer use different objects"
            );
            ensure!(
                offset + 16 <= ctx_size,
                "license key outside serialized context"
            );
            license_keys.push(offset);
        }
        license_keys.sort_unstable();
        license_keys.dedup();
        ensure!(license_keys.len() <= 1, "ambiguous license XOR sources");
        Ok(ImportFields {
            descriptor: descriptor as usize,
            name_key: name_keys[0],
            license_key: license_keys.pop(),
            flag_size: flag_size.context("import parser does not expose its flag width")?,
        })
    }

    fn scalar(&self, image: &mut Image, index: usize, register: usize) -> Result<Option<u32>> {
        let raw = self.records[index];
        if u32_at(raw, 0)? == 0x231 {
            return Ok(self.extension(image, index)?[register].get());
        }
        (u32_at(raw, 0)? == 0x52
            && u32_at(raw, 12)? == 0x8c
            && u32_at(raw, 16)? == 0x25 + register as u32
            && u32_at(raw, 32)? == 0x8f)
            .then(|| u32_at(raw, 48))
            .transpose()
    }

    fn register_copy(
        &self,
        image: &mut Image,
        index: usize,
        dest: usize,
        source: usize,
    ) -> Result<bool> {
        let raw = self.records[index];
        if u32_at(raw, 0)? == 0x231 {
            return Ok(self.extension(image, index)?[dest] == Value::input(100 + source as u32));
        }
        Ok(u32_at(raw, 0)? == 0x52
            && u32_at(raw, 12)? == 0x8c
            && u32_at(raw, 16)? == 0x25 + dest as u32
            && u32_at(raw, 32)? == 0x8c
            && u32_at(raw, 36)? == 0x25 + source as u32)
    }

    fn register_offset(
        &self,
        image: &mut Image,
        index: usize,
        register: usize,
    ) -> Result<Option<u32>> {
        let raw = self.records[index];
        if u32_at(raw, 0)? == 0x4d
            && u32_at(raw, 12)? == 0x8c
            && u32_at(raw, 16)? == 0x25 + register as u32
            && u32_at(raw, 32)? == 0x8f
        {
            return Ok(Some(u32_at(raw, 48)?));
        }
        if u32_at(raw, 0)? != 0x231 {
            return Ok(None);
        }
        let mut offset = None;
        for seed in [0x41000000u32, 0x57391820, 0x6b9e207c] {
            let input = std::array::from_fn(|r| {
                Value::constant(seed.wrapping_add((r as u32 + 1).wrapping_mul(0x10379)))
            });
            let output = self.extension_inputs(image, index, input)?;
            let Some(value) = output[register].get() else {
                return Ok(None);
            };
            let delta = value.wrapping_sub(input[register].get().unwrap());
            if output
                .iter()
                .zip(input)
                .enumerate()
                .any(|(r, (out, input))| r != register && *out != input)
                || offset.is_some_and(|old| old != delta)
            {
                return Ok(None);
            }
            offset = Some(delta);
        }
        Ok(offset)
    }

    fn copy_function(&self, target: u32) -> bool {
        let Some(bytes) = self.image.get(target as usize..target as usize + 8) else {
            return false;
        };
        let mut d = Decoder::with_ip(32, bytes, BASE as u64 + target as u64, DecoderOptions::NONE);
        let exchange = d.decode();
        let call = d.decode();
        let ret = d.decode();
        if exchange.mnemonic() != M::Xchg
            || exchange.op0_register() != Register::EDX
            || exchange.op1_register() != Register::EAX
            || call.mnemonic() != M::Call
            || call.op0_kind() != OpKind::NearBranch32
            || ret.mnemonic() != M::Ret
        {
            return false;
        }
        let Some(at) = call.near_branch32().checked_sub(BASE) else {
            return false;
        };
        let Some(code) = self.image.get(at as usize..at as usize + 96) else {
            return false;
        };
        let instructions = Decoder::new(32, code, DecoderOptions::NONE)
            .into_iter()
            .collect::<Vec<_>>();
        instructions
            .iter()
            .any(|i| i.mnemonic() == M::Movsd && i.has_rep_prefix())
            && instructions
                .iter()
                .any(|i| i.mnemonic() == M::Movsb && i.has_rep_prefix())
    }

    /// The reader passes destination in EAX, stream pointer in EDX and size in
    /// ECX. The writer reverses the first two arguments and is not a projection.
    pub(super) fn projection(&self) -> Result<Vec<(usize, usize)>> {
        let mut image = Image::default();
        image.add(BASE, self.image.to_vec())?;
        let mut wrappers = std::collections::HashMap::new();
        let mut groups: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut last = None;
        for index in 5..self.records.len() {
            let raw = self.records[index];
            if u32_at(raw, 0)? != 0x60 || u32_at(raw, 12)? != 0x90 {
                continue;
            }
            let target = u32_at(raw, 28)?;
            let copy = *wrappers
                .entry(target)
                .or_insert_with(|| self.copy_function(target));
            if !copy {
                continue;
            }
            let address = self.records[index - 3];
            if !matches!(u32_at(address, 0)?, 0x4d | 0x231) {
                continue;
            }
            let Some(size) = self.scalar(&mut image, index - 5, 3)? else {
                continue;
            };
            if !(8..=0x100000).contains(&size) {
                continue;
            }
            if !self.register_copy(&mut image, index - 2, 1, 3)?
                || !self.register_copy(&mut image, index - 1, 2, 6)?
            {
                continue;
            }
            let Some(dest) = self.register_offset(&mut image, index - 3, 0)? else {
                continue;
            };
            if !(1..0x100000).contains(&dest) {
                continue;
            }
            if last.and_then(|previous: usize| previous.checked_add(7)) != Some(index) {
                groups.push(Vec::new());
            }
            groups
                .last_mut()
                .unwrap()
                .push((dest as usize, size as usize));
            last = Some(index);
        }
        groups.retain(|g| {
            g.len() >= 3
                && g.last().is_some_and(|&(_, n)| n > 0x1000)
                && g.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0)
        });
        ensure!(
            groups.len() == 1,
            "cannot uniquely derive configuration reader: {} projections",
            groups.len()
        );
        Ok(groups.pop().unwrap())
    }

    /// Recover the registry's count and stride from its lookup loop, then
    /// identify the replacement-function column by its interpreter transfers.
    pub fn hooks(&self) -> Result<std::collections::HashMap<u32, (String, String)>> {
        let mut image = Image::default();
        image.add(BASE, self.image.to_vec())?;
        let mut registries = Vec::new();
        let global = |raw: &[u8], register: u32| -> Result<Option<usize>> {
            (u32_at(raw, 0)? == 0x52
                && u32_at(raw, 12)? == 0x8c
                && u32_at(raw, 16)? == 0x25 + register
                && u32_at(raw, 32)? == 0x8d
                && u32_at(raw, 36)? == 0
                && u32_at(raw, 40)? == 0
                && u32_at(raw, 44)? & 1 != 0)
                .then(|| u32_at(raw, 48).map(|at| at as usize))
                .transpose()
        };
        for index in 1..self.records.len().saturating_sub(2) {
            let Some(hooks) = global(self.records[index], 3)? else {
                continue;
            };
            let Some(names) = global(self.records[index + 1], 0)? else {
                continue;
            };
            let Some(count) = self.scalar(&mut image, index - 1, 6)? else {
                continue;
            };
            if !(1..=65536).contains(&count) {
                continue;
            }
            for end in index + 4..(index + 64).min(self.records.len() - 1) {
                let decrement = self.records[end];
                let branch = self.records[end + 1];
                if u32_at(decrement, 0)? != 1
                    || u32_at(decrement, 12)? != 0x8c
                    || u32_at(decrement, 16)? != 0x2b
                    || u32_at(branch, 0)? != 0x2d
                    || u32_at(branch, 12)? != 0x90
                {
                    continue;
                }
                let head = u32_at(branch, 28)? as usize;
                if !(index + 2..end).contains(&head) {
                    continue;
                }
                let step = self.records[end - 2];
                if u32_at(step, 0)? != 0x4d
                    || u32_at(step, 12)? != 0x8d
                    || u32_at(step, 32)? != 0x8f
                    || u32_at(step, 48)? != 8
                {
                    break;
                }
                let Some(stride) = self.register_offset(&mut image, end - 1, 3)? else {
                    break;
                };
                ensure!(
                    (4..=1024).contains(&stride) && stride.is_multiple_of(4),
                    "invalid API registry stride"
                );
                registries.push((names, hooks, count as usize, stride as usize));
                break;
            }
        }
        registries.sort_unstable();
        registries.dedup();
        ensure!(
            registries.len() == 1,
            "cannot uniquely derive API registry: {} loops",
            registries.len()
        );
        let (names, hooks, count, stride) = registries[0];
        let names = u32_at(self.image, names)?
            .checked_sub(BASE)
            .context("name table below Loader")? as usize;
        let hooks = u32_at(self.image, hooks)?
            .checked_sub(BASE)
            .context("hook table below Loader")? as usize;
        take(self.image, names, count * 8)?;
        take(self.image, hooks, count * stride)?;
        let mut columns = Vec::new();
        for offset in (0..stride).step_by(4) {
            let mut tokens = Vec::new();
            for index in 0..count {
                let target = u32_at(self.image, hooks + index * stride + offset)?;
                let Some(at) = target.checked_sub(BASE) else {
                    break;
                };
                let Some(code) = self.image.get(at as usize..).filter(|b| b.len() >= 5) else {
                    break;
                };
                let jump = Decoder::with_ip(32, code, target as u64, DecoderOptions::NONE).decode();
                if jump.mnemonic() != M::Jmp || jump.op0_kind() != OpKind::NearBranch32 {
                    break;
                }
                let Some(at) = jump.near_branch32().checked_sub(BASE) else {
                    break;
                };
                let Some(code) = self.image.get(at as usize..).filter(|b| b.len() >= 10) else {
                    break;
                };
                let mut d =
                    Decoder::with_ip(32, code, BASE as u64 + at as u64, DecoderOptions::NONE);
                let push = d.decode();
                let jump = d.decode();
                if push.mnemonic() != M::Push
                    || push.op0_kind() != OpKind::Immediate32
                    || jump.mnemonic() != M::Jmp
                    || jump.op0_kind() != OpKind::NearBranch32
                    || jump.near_branch32() != BASE + self.dispatch
                {
                    break;
                }
                let token = push.immediate32() ^ self.key;
                ensure!(
                    (token as usize) < self.records.len(),
                    "API replacement token outside interpreter table"
                );
                tokens.push(token);
            }
            if tokens.len() == count {
                columns.push(tokens);
            }
        }
        ensure!(
            columns.len() == 1,
            "cannot uniquely derive API replacement column"
        );
        let mut result = std::collections::HashMap::new();
        for (index, token) in columns.pop().unwrap().into_iter().enumerate() {
            let mut strings = Vec::new();
            for field in 0..2 {
                let at = u32_at(self.image, names + index * 8 + field * 4)?
                    .checked_sub(BASE)
                    .context("API name below Loader")? as usize;
                let bytes = self.image.get(at..).context("API name outside Loader")?;
                let length = bytes
                    .iter()
                    .take(4096)
                    .position(|&b| b == 0)
                    .context("unterminated API name")?;
                ensure!(
                    length > 0 && bytes[..length].iter().all(|b| (32..127).contains(b)),
                    "invalid API name"
                );
                strings.push(String::from_utf8(bytes[..length].to_vec())?);
            }
            let name = strings.pop().unwrap();
            let dll = strings.pop().unwrap();
            ensure!(
                result.insert(token, (dll, name)).is_none(),
                "duplicate API replacement token"
            );
        }
        Ok(result)
    }
}
