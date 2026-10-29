use anyhow::{Context, Result, ensure};

use super::entry;
use crate::{
    common::{
        codec::{self, expanded_size},
        crypto,
        io::{take, u32_at},
        pe::Pe,
    },
    devirt::vm,
};

#[derive(Clone, Debug)]
pub struct Descriptor {
    pub index: usize,
    pub enabled: bool,
    pub flags: u32,
    pub packed_size: usize,
    pub expanded_size: usize,
    pub rva: u32,
    /// Original IMAGE_SECTION_HEADER.Characteristics, not the packed file's
    /// temporary writable/executable protection or the compression flags.
    pub characteristics: u32,
    pub seed: [u8; 16],
    pub crc32: u32,
}

pub struct Configuration {
    pub descriptors: Vec<Descriptor>,
    /// Original packed-section bytes displaced by the protector's entry jump.
    pub entry_patch: Option<super::extract::Recovered>,
    pub ctx: Option<Vec<u8>>,
    pub loader: Option<Vec<u8>>,
    pub layout: Option<vm::Layout>,
}

fn derive_key(pe: &Pe<'_>, count: usize, skip_shared: bool) -> Result<[u8; 16]> {
    let mut key = [0; 16];
    for section in &pe.sections[..count] {
        if skip_shared && section.characteristics & 0x10000000 != 0 {
            continue;
        }
        let raw = if section.raw_size == 0 {
            &[][..]
        } else {
            take(
                pe.data,
                section.raw_offset as usize,
                section.raw_size as usize,
            )?
        };
        for (byte, digest) in key.iter_mut().zip(md5::compute(raw).0) {
            *byte ^= digest;
        }
    }
    Ok(key)
}

pub fn parse(pe: &Pe<'_>) -> Result<Configuration> {
    let entry = entry::parse(pe)?;
    let loader = entry.loader;
    let layout = loader.as_deref().map(vm::Layout::parse).transpose()?;
    decode_metadata(pe, entry.metadata, loader, layout)
        .with_context(|| format!("metadata at {:#x}", entry.metadata))
}

fn decode_metadata(
    pe: &Pe<'_>,
    rva: u32,
    loader: Option<Vec<u8>>,
    layout: Option<vm::Layout>,
) -> Result<Configuration> {
    let header = pe.read(rva, 28)?;
    let count = u32_at(header, 0)? as usize;
    ensure!(
        count > 0 && count <= pe.sections.len(),
        "invalid metadata key section count"
    );
    let packed_size = u32_at(header, 4)? as usize;
    ensure!(packed_size > 0, "empty metadata ciphertext");
    let expected = expanded_size(u32_at(header, 8)? as usize)?;
    let ciphertext = pe.read(
        rva.checked_add(28).context("metadata RVA overflow")?,
        packed_size,
    )?;
    ensure!(
        md5::compute(ciphertext).0 == header[12..28],
        "metadata ciphertext MD5 mismatch"
    );
    let mut decoded = None;
    for skip_shared in [true, false] {
        let key = derive_key(pe, count, skip_shared)?;
        let packed = crypto::decipher(ciphertext, &key);
        if let Ok(plain) = codec::decompress(&packed, expected, true)
            && plain.len() >= 16
            && md5::compute(&plain[16..]).0 == plain[..16]
        {
            decoded = Some(plain);
            break;
        }
    }
    let plain = decoded.context("metadata RC4/LZ/plaintext MD5 verification failed")?;
    let patch_size = u32_at(&plain, 16)? as usize;
    let entry_patch = if patch_size == 0 {
        None
    } else {
        Some(super::extract::Recovered {
            rva: u32_at(&plain, 20)?,
            bytes: take(&plain, 24, patch_size)?.to_vec(),
        })
    };
    let count_at = 24usize
        .checked_add(patch_size)
        .context("patch size overflow")?;
    let descriptor_count = u32_at(&plain, count_at)? as usize;
    ensure!(
        descriptor_count > 0 && descriptor_count <= pe.sections.len(),
        "invalid descriptor count"
    );
    let table_at = count_at + 4;
    let table = take(&plain, table_at, descriptor_count * 80)?;
    let mut descriptors = Vec::with_capacity(descriptor_count);
    for (index, raw) in table.as_chunks::<80>().0.iter().enumerate() {
        let expanded_size = u32_at(raw, 12)? as usize;
        if raw[0] != 0 {
            crate::common::codec::expanded_size(expanded_size)?;
        }
        descriptors.push(Descriptor {
            index,
            enabled: raw[0] != 0,
            flags: u32_at(raw, 4)?,
            packed_size: u32_at(raw, 8)? as usize,
            expanded_size,
            rva: u32_at(raw, 16)?,
            characteristics: u32_at(raw, 36)?,
            seed: take(raw, 20, 16)?.try_into()?,
            crc32: u32_at(raw, 60)?,
        });
    }
    // Project serialized bytes using the Loader reader's copy operations.
    let mut at = table_at + table.len();
    let records20 = u32_at(&plain, at)? as usize;
    ensure!(records20 <= 0x10000, "invalid 20-byte record count");
    at += 4;
    take(&plain, at, records20 * 20)?;
    at += records20 * 20;
    let pairs = u32_at(&plain, at)? as usize;
    ensure!(pairs <= 0x10000, "invalid pair count");
    at += 4;
    take(&plain, at, pairs * 8)?;
    at += pairs * 8;
    let ctx = if let Some(layout) = layout.as_ref() {
        ensure!(
            plain.len() - at == layout.copies.iter().map(|(_, size)| size).sum::<usize>(),
            "serialized config length disagrees with Loader reader"
        );
        let size = layout
            .copies
            .iter()
            .map(|(dest, size)| dest + size)
            .max()
            .unwrap();
        let mut ctx = vec![0; size];
        for &(dest, size) in &layout.copies {
            ctx[dest..dest + size].copy_from_slice(take(&plain, at, size)?);
            at += size;
        }
        Some(ctx)
    } else {
        None
    };
    Ok(Configuration {
        descriptors,
        ctx,
        entry_patch,
        loader,
        layout,
    })
}
