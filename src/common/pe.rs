use anyhow::{Context, Result, bail, ensure};

use super::io::{take, u16_at, u32_at, u64_at};

#[derive(Debug)]
pub struct Section {
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub header_offset: usize,
}

pub struct Pe<'a> {
    pub data: &'a [u8],
    pub nt: usize,
    pub optional: usize,
    pub is_64: bool,
    pub entry: u32,
    pub image_base: u64,
    pub image_size: u32,
    pub headers_size: u32,
    pub file_alignment: u32,
    pub sections: Vec<Section>,
}

impl<'a> Pe<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        ensure!(take(data, 0, 2)? == b"MZ", "missing MZ signature");
        let nt = u32_at(data, 0x3c)? as usize;
        ensure!(take(data, nt, 4)? == b"PE\0\0", "missing PE signature");
        let machine = u16_at(data, nt + 4)?;
        let count = u16_at(data, nt + 6)? as usize;
        ensure!(
            (1..=1024).contains(&count),
            "invalid PE section count {count}"
        );
        let optional = nt + 24;
        let optional_size = u16_at(data, nt + 20)? as usize;
        ensure!(optional_size >= 96, "truncated optional header");
        take(data, optional, optional_size)?;
        let is_64 = match (machine, u16_at(data, optional)?) {
            (0x14c, 0x10b) => false,
            (0x8664, 0x20b) => true,
            _ => bail!("only x86 PE32 and x64 PE32+ are supported"),
        };
        let mut sections = Vec::with_capacity(count);
        for index in 0..count {
            let at = optional + optional_size + index * 40;
            let header = take(data, at, 40)?;
            let raw_offset = u32_at(header, 20)?;
            let raw_size = u32_at(header, 16)?;
            if raw_size != 0 {
                take(data, raw_offset as usize, raw_size as usize)?;
            }
            sections.push(Section {
                virtual_size: u32_at(header, 8)?,
                rva: u32_at(header, 12)?,
                raw_size,
                raw_offset,
                characteristics: u32_at(header, 36)?,
                header_offset: at,
            });
        }
        // Zero-extent section headers occupy no RVA range. Keep their header
        // indices, but do not let them conflict with or shadow mapped sections.
        let mut sorted: Vec<_> = sections
            .iter()
            .filter(|s| s.virtual_size != 0 || s.raw_size != 0)
            .map(|s| s.rva)
            .collect();
        sorted.sort_unstable();
        ensure!(
            !sorted.windows(2).any(|w| w[0] == w[1]),
            "duplicate section RVA"
        );
        let file_alignment = u32_at(data, optional + 36)?;
        ensure!(
            file_alignment.is_power_of_two() && file_alignment <= 0x10000,
            "invalid FileAlignment"
        );
        Ok(Self {
            data,
            nt,
            optional,
            is_64,
            entry: u32_at(data, optional + 16)?,
            image_base: if is_64 {
                u64_at(data, optional + 24)?
            } else {
                u32_at(data, optional + 28)? as u64
            },
            image_size: u32_at(data, optional + 56)?,
            headers_size: u32_at(data, optional + 60)?,
            file_alignment,
            sections,
        })
    }

    pub fn section_at(&self, rva: u32) -> Option<&Section> {
        // Choose the highest preceding RVA to handle overlapping raw extents.
        self.sections
            .iter()
            .filter(|s| rva >= s.rva && (s.virtual_size != 0 || s.raw_size != 0))
            .max_by_key(|s| s.rva)
            .filter(|s| (rva - s.rva) < s.virtual_size.max(s.raw_size))
    }

    pub fn read(&self, rva: u32, size: usize) -> Result<&'a [u8]> {
        let end = (rva as u64)
            .checked_add(size as u64)
            .context("RVA overflow")?;
        ensure!(end <= self.image_size as u64, "RVA range is outside image");
        if end <= self.headers_size as u64 {
            return take(self.data, rva as usize, size);
        }
        let section = self
            .section_at(rva)
            .with_context(|| format!("no section for RVA {rva:#x}"))?;
        let delta = (rva - section.rva) as usize;
        let next = self
            .sections
            .iter()
            .filter(|s| s.rva > section.rva && (s.virtual_size != 0 || s.raw_size != 0))
            .map(|s| s.rva)
            .min();
        ensure!(
            next.is_none_or(|next| end <= next as u64),
            "RVA range overlaps next section"
        );
        ensure!(
            delta + size <= section.raw_size as usize,
            "RVA range is not file backed"
        );
        let offset = section.raw_offset as usize + delta;
        take(self.data, offset, size)
    }
}

pub fn checksum(bytes: &[u8], field: usize) -> u32 {
    let mut sum = 0u64;
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let at = i * 2;
        if at >= field && at < field + 4 {
            continue;
        }
        let word = chunk[0] as u64 + ((chunk.get(1).copied().unwrap_or(0) as u64) << 8);
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32).wrapping_add(bytes.len() as u32)
}
