//! Enigma's encrypted Virtual Box container. Its PRGA starts from arbitrary
//! stored byte tables; they are not necessarily permutations produced by RC4 KSA.
use anyhow::{Context, Result, bail, ensure};
use std::path::PathBuf;

use crate::{
    common::{
        codec::{self, expanded_size},
        io::{take, u32_at, u64_at},
        pe::Pe,
    },
    unpack::config::Configuration,
};

pub struct File {
    pub path: PathBuf,
    pub data: Vec<u8>,
}

fn decipher(data: &[u8], initial: &[u8; 256]) -> Vec<u8> {
    let mut s = *initial;
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&byte| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            byte ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}
impl Cursor<'_> {
    fn read(&mut self, n: usize) -> Result<&[u8]> {
        let bytes = take(self.data, self.at, n)?;
        self.at += n;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.read(1)?[0])
    }
    fn dword(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read(4)?.try_into()?))
    }
    fn qword(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read(8)?.try_into()?))
    }
    fn name(&mut self) -> Result<String> {
        let mut words = Vec::new();
        loop {
            let word = u16::from_le_bytes(self.read(2)?.try_into()?);
            if word == 0 {
                return Ok(String::from_utf16(&words)?);
            }
            words.push(word);
        }
    }
}

struct Node {
    path: PathBuf,
    size: usize,
    offset: usize,
    stored: usize,
}

fn path(parent: &std::path::Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name == "%DEFAULT FOLDER%" {
        return Ok(parent.to_path_buf());
    }
    ensure!(!name.starts_with(['/', '\\']), "absolute EVB path: {name}");
    let mut result = parent.to_path_buf();
    for part in name.split(['/', '\\']) {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.chars().any(|c| c < ' ' || "<>:\"|?*".contains(c))
                && !device
                && !part.ends_with(['.', ' '])
                && !(part.starts_with('%') && part.ends_with('%')),
            "unsupported EVB path component: {part}"
        );
        result.push(part);
    }
    Ok(result)
}

fn directory(tree: &[u8]) -> Result<Vec<Node>> {
    let mut c = Cursor { data: tree, at: 0 };
    // Iterative traversal avoids a host stack overflow on deep directory trees.
    let mut pending = vec![(PathBuf::new(), 1u32)];
    let mut files = Vec::new();
    while let Some((parent, remaining)) = pending.pop() {
        if remaining == 0 {
            continue;
        }
        pending.push((parent.clone(), remaining - 1));
        c.dword()?; // Node identifier.
        c.dword()?; // Node index.
        let children = c.dword()?;
        ensure!(
            children as usize <= tree.len() / 15,
            "invalid EVB child count"
        );
        let name = c.name()?;
        let kind = c.byte()?;
        let path = path(&parent, &name)?;
        match kind {
            0 | 1 => {} // Main node or logical root.
            3 => {
                c.read(30)?;
            } // Policy, three Delphi dates, attributes, flag.
            2 => {
                ensure!(
                    !path.as_os_str().is_empty() && children == 0,
                    "invalid EVB file node"
                );
                c.read(2)?; // File flags and extraction policy.
                let size = usize::try_from(c.qword()?)?;
                ensure!(
                    size <= crate::common::codec::MAX_EXPANDED,
                    "EVB file exceeds expansion limit"
                );
                c.read(29)?; // Dates, attributes, flag.
                c.name()?; // Optional alternate name.
                c.byte()?;
                let offset = usize::try_from(c.qword()?)?;
                let stored = usize::try_from(c.qword()?)?;
                files.push(Node {
                    path: path.clone(),
                    size,
                    offset,
                    stored,
                });
            }
            _ => bail!("unknown EVB node kind {kind}"),
        }
        if children != 0 {
            pending.push((path, children));
        }
    }
    ensure!(c.at == tree.len(), "unparsed EVB directory bytes");
    Ok(files)
}

fn interleaved_directory(container: &[u8], state: &[u8; 256]) -> Result<Vec<Node>> {
    let mut at = 120usize;
    let mut pending = vec![(PathBuf::new(), 1u32)];
    let mut files = Vec::new();
    while let Some((parent, remaining)) = pending.pop() {
        if remaining == 0 {
            continue;
        }
        pending.push((parent.clone(), remaining - 1));
        let size = u32_at(&decipher(take(container, at, 4)?, state), 0)? as usize;
        at += 4;
        let record = decipher(take(container, at, size)?, state);
        at += size;
        let mut c = Cursor {
            data: &record,
            at: 0,
        };
        c.dword()?;
        c.dword()?;
        let children = c.dword()?;
        ensure!(
            children as usize <= container.len() / 15,
            "invalid EVB child count"
        );
        let label = c.name()?;
        let kind = c.byte()?;
        let item = path(&parent, &label)?;
        match kind {
            0 | 1 | 3 => {}
            2 => {
                ensure!(
                    !item.as_os_str().is_empty() && children == 0,
                    "invalid EVB file node"
                );
                c.read(2)?;
                let size = usize::try_from(c.qword()?)?;
                ensure!(
                    size <= crate::common::codec::MAX_EXPANDED,
                    "EVB file exceeds expansion limit"
                );
                c.read(29)?;
                c.name()?;
                let stored = usize::try_from(c.qword()?)?;
                ensure!(c.at == record.len(), "unparsed interleaved EVB file record");
                take(container, at, stored)?;
                files.push(Node {
                    path: item.clone(),
                    size,
                    offset: at,
                    stored,
                });
                at += stored;
            }
            _ => bail!("unknown EVB node kind {kind}"),
        }
        if children != 0 {
            pending.push((item, children));
        }
        ensure!(files.len() <= 0x100000, "too many EVB files");
    }
    ensure!(
        at == container.len(),
        "unparsed interleaved EVB container bytes"
    );
    Ok(files)
}

fn file_data(stored: &[u8], size: usize, compressed: bool, state: &[u8; 256]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    if compressed {
        let count = size.div_ceil(65536);
        take(stored, 0, count * 12)?;
        let mut end = count * 12;
        for index in 0..count {
            // Both each index record and each compressed block restart PRGA.
            let record = decipher(&stored[index * 12..index * 12 + 12], state);
            let offset = usize::try_from(u64_at(&record, 0)?)?;
            let packed = u32_at(&record, 8)? as usize;
            ensure!(offset == end && packed != 0, "invalid EVB block extent");
            let plain = decipher(take(stored, offset, packed)?, state);
            output.extend(codec::decompress(
                &plain,
                (size - output.len()).min(65536),
                false,
            )?);
            end = offset + packed;
        }
        ensure!(end == stored.len(), "unparsed compressed EVB file bytes");
    } else {
        ensure!(stored.len() == size, "plain EVB stored size mismatch");
        output.reserve(size);
        for block in stored.chunks(8192) {
            output.extend(decipher(block, state));
        }
    }
    Ok(output)
}

#[derive(PartialEq, Eq)]
struct Located {
    table: usize,
    base: usize,
    length: usize,
    version: u32,
}

/// Derive the embedded container from the recovered configuration image.
/// The four 256-byte PRGA state tables are consecutive. The length/bias pair
/// consists of two u32 fields aligned to four bytes after those tables. The
/// decrypted 64-byte header validates the candidate table, length and
/// section-relative offset: it repeats the total length at +48, places the
/// directory at +120, and length(+32) + 120 equals the total length.
fn locate(pe: &Pe<'_>, ctx: &[u8]) -> Result<Option<Located>> {
    let mut found = Vec::new();
    for table in 0..ctx.len() {
        let length_at = (table + 0x400).next_multiple_of(4);
        let Some(fields) = ctx.get(length_at..length_at + 8) else {
            continue;
        };
        let length = u32_at(fields, 0)? as usize;
        let bias = u32_at(fields, 4)? as usize;
        if length < 120 {
            continue;
        }
        for section in &pe.sections {
            if bias
                .checked_add(length)
                .is_none_or(|end| end > section.raw_size as usize)
            {
                continue;
            }
            let Some(base) = (section.raw_offset as usize).checked_add(bias) else {
                continue;
            };
            let Some(header_at) = base.checked_add(56) else {
                continue;
            };
            if header_at
                .checked_add(64)
                .is_none_or(|end| end > pe.data.len())
            {
                continue;
            }
            let metadata: &[u8; 256] = take(ctx, table, 256)?.try_into()?;
            let header = decipher(take(pe.data, header_at, 64)?, metadata);
            if u32_at(&header, 4)? != 64
                || u64_at(&header, 48)? != length as u64
                || u64_at(&header, 24)? != 120
                || u64_at(&header, 32)?.checked_add(120) != Some(length as u64)
            {
                continue;
            }
            let version = u32_at(&header, 20)?;
            ensure!(
                matches!(version, 1 | 3),
                "unsupported EVB directory version {version}"
            );
            found.push(Located {
                table,
                base,
                length,
                version,
            });
        }
    }
    found.sort_by_key(|c| (c.table, c.base, c.length, c.version));
    found.dedup();
    ensure!(
        found.len() <= 1,
        "expected one embedded EVB container, found {}",
        found.len()
    );
    Ok(found.pop())
}

fn decode_files(
    nodes: &[Node],
    data: &[u8],
    state: &[u8; 256],
    compressed: bool,
) -> Result<Vec<File>> {
    nodes
        .iter()
        .map(|node| {
            let bytes = file_data(
                take(data, node.offset, node.stored)?,
                node.size,
                compressed,
                state,
            )
            .with_context(|| format!("EVB file {}", node.path.display()))?;
            Ok(File {
                path: node.path.clone(),
                data: bytes,
            })
        })
        .collect()
}

/// One storage mode applies to the entire container. Plain files have no index or
/// padding; compressed files have a complete 12-byte index and independent LZ
/// streams. Never resolve equal-size, dual-valid encodings by preferring a mode.
fn stored_files(nodes: &[Node], data: &[u8], state: &[u8; 256]) -> Result<Vec<File>> {
    let plain = nodes.iter().all(|n| n.stored == n.size);
    if plain && nodes.iter().all(|n| n.size == 0) {
        return decode_files(nodes, data, state, false);
    }
    match (plain, decode_files(nodes, data, state, true)) {
        (true, Ok(_)) => {
            bail!("ambiguous EVB storage: both plain and compressed layouts are valid")
        }
        (true, Err(_)) => decode_files(nodes, data, state, false),
        (false, Ok(files)) => Ok(files),
        (false, Err(error)) => Err(error).context("invalid compressed EVB storage"),
    }
}

/// Recover files from the validated x86 configuration without starting a process.
/// No validated container produces a warning and an empty list, not proof of absence.
pub fn extract(pe: &Pe<'_>, config: &Configuration) -> Result<Vec<File>> {
    let ctx = config.ctx.as_ref().context("unknown ctx layout")?;
    let Some(container) = locate(pe, ctx)? else {
        eprintln!(
            "WARNING: EVB status unconfirmed: no valid embedded container was found. EVB may be disabled, unsupported, or damaged; only EXE recovery is confirmed."
        );
        return Ok(Vec::new());
    };
    let metadata: &[u8; 256] = take(ctx, container.table, 256)?.try_into()?;
    let content: &[u8; 256] = take(ctx, container.table + 0x100, 256)?.try_into()?;
    let container_data = take(pe.data, container.base, container.length)?;
    let (nodes, data) = if container.version == 1 {
        let nodes = interleaved_directory(container_data, metadata)?;
        (nodes, container_data)
    } else {
        let packed = u32_at(&decipher(take(container_data, 120, 4)?, metadata), 0)? as usize;
        let expected =
            expanded_size(u32_at(&decipher(take(container_data, 124, 4)?, metadata), 0)? as usize)?;
        let tree = codec::decompress(
            &decipher(take(container_data, 128, packed)?, metadata),
            expected,
            true,
        )?;
        let nodes = directory(&tree)?;
        let data = take(
            container_data,
            128 + packed,
            container_data.len() - (128 + packed),
        )?;
        (nodes, data)
    };
    let mut paths = std::collections::HashSet::new();
    for node in &nodes {
        ensure!(
            paths.insert(node.path.to_string_lossy().to_lowercase()),
            "duplicate EVB output path"
        );
    }
    let files = stored_files(&nodes, data, content)?;
    for file in &files {
        eprintln!("EVB: {} ({} bytes)", file.path.display(), file.data.len());
    }
    Ok(files)
}

#[cfg(test)]
#[path = "../../test/evb.rs"]
mod tests;
