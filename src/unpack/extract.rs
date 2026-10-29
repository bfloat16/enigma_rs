use anyhow::{Context, Result, ensure};

use super::config::{Configuration, Descriptor};
use crate::common::{codec, crypto, pe::Pe};

pub struct StoredSection {
    pub descriptor: Descriptor,
    pub ciphertext: Vec<u8>,
}

pub fn stored_sections(pe: &Pe<'_>, config: &Configuration) -> Result<Vec<StoredSection>> {
    let mut sections = Vec::new();
    for descriptor in config
        .descriptors
        .iter()
        .take_while(|d| d.rva != 0)
        .filter(|d| d.enabled)
    {
        let end = descriptor.rva as u64 + descriptor.expanded_size as u64;
        ensure!(
            end <= pe.image_size as u64,
            "section expansion is outside image"
        );
        let ciphertext = if descriptor.packed_size == 0 {
            Vec::new()
        } else {
            pe.read(descriptor.rva, descriptor.packed_size)?.to_vec()
        };
        sections.push(StoredSection {
            descriptor: descriptor.clone(),
            ciphertext,
        });
    }
    ensure!(!sections.is_empty(), "no enabled sections");
    if let Some(patch) = &config.entry_patch {
        let mut targets = sections.iter_mut().filter_map(|section| {
            let offset = patch.rva.checked_sub(section.descriptor.rva)? as usize;
            let end = offset.checked_add(patch.bytes.len())?;
            (end <= section.ciphertext.len()).then_some((section, offset, end))
        });
        let (section, offset, end) = targets
            .next()
            .context("bootstrap patch is outside stored host sections")?;
        ensure!(
            targets.next().is_none(),
            "ambiguous bootstrap patch destination"
        );
        section.ciphertext[offset..end].copy_from_slice(&patch.bytes);
    }
    Ok(sections)
}

pub fn decode(section: &StoredSection, salt: Option<u32>, filter: bool) -> Result<Vec<u8>> {
    let d = &section.descriptor;
    if d.packed_size == 0 {
        return Ok(vec![0; d.expanded_size]);
    }
    let packed = if d.flags & 8 != 0 {
        match salt {
            Some(value) => {
                crypto::decipher(&section.ciphertext, &crypto::section_key(&d.seed, value))
            }
            None => crypto::decipher(&section.ciphertext, &d.seed),
        }
    } else {
        section.ciphertext.clone()
    };
    let crc = crc32fast::hash(&packed);
    ensure!(
        crc == d.crc32,
        "section {} CRC32 mismatch: {crc:08x} != {:08x}",
        d.index,
        d.crc32
    );
    let mut expanded = if d.flags & 1 != 0 {
        codec::decompress(&packed, d.expanded_size, true)
            .with_context(|| format!("section {} LZ verification failed", d.index))?
    } else {
        ensure!(
            packed.len() == d.expanded_size,
            "uncompressed section size mismatch"
        );
        packed
    };
    if filter && d.flags & 4 != 0 {
        codec::fix_branches(&mut expanded);
    }
    Ok(expanded)
}

pub fn verify_all(sections: &[StoredSection], salt: Option<u32>) -> Result<()> {
    for section in sections {
        decode(section, salt, false)?;
    }
    Ok(())
}

pub struct Recovered {
    pub rva: u32,
    pub bytes: Vec<u8>,
}

pub fn recover(sections: &[StoredSection], salt: Option<u32>) -> Result<Vec<Recovered>> {
    sections
        .iter()
        .map(|section| {
            Ok(Recovered {
                rva: section.descriptor.rva,
                bytes: decode(section, salt, true)?,
            })
        })
        .collect()
}
