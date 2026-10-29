//! Salt enumeration using every available logical CPU core.
use super::{
    extract::{StoredSection, verify_all},
    search::{UINT32_END, finish_progress, progress},
};
use crate::common::{
    codec,
    crypto::{Rc4, SectionProbe},
};
use anyhow::{Context, Result};
use std::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

const CHUNK: u64 = 4096;

fn screen_matches(section: &StoredSection, mut cipher: Rc4) -> bool {
    let data = &section.ciphertext;
    let mut prefix = [0u8; 64];
    let length = data.len().min(prefix.len());
    let first = length.min(8);
    for (out, &byte) in prefix[..first].iter_mut().zip(data) {
        *out = cipher.byte(byte);
    }
    // Most wrong keys already produce an impossible LZ token in eight bytes.
    // Prefix exhaustion is inconclusive, so this cannot discard a valid key.
    if section.descriptor.flags & 1 != 0
        && !codec::plausible_prefix(
            &prefix[..first],
            data.len(),
            section.descriptor.expanded_size,
        )
    {
        return false;
    }
    for (out, &byte) in prefix[first..length].iter_mut().zip(&data[first..]) {
        *out = cipher.byte(byte);
    }
    if section.descriptor.flags & 1 != 0
        && !codec::plausible_prefix(
            &prefix[..length],
            data.len(),
            section.descriptor.expanded_size,
        )
    {
        return false;
    }
    let mut crc = crc32fast::Hasher::new();
    crc.update(&prefix[..length]);
    let mut block = [0u8; 256];
    for chunk in data[length..].chunks(block.len()) {
        for (out, &byte) in block.iter_mut().zip(chunk) {
            *out = cipher.byte(byte);
        }
        crc.update(&block[..chunk.len()]);
    }
    crc.finalize() == section.descriptor.crc32
}

pub fn search(sections: &[StoredSection], screen: &StoredSection) -> Result<u32> {
    find(sections, screen, 0..UINT32_END)?.context("no salt passed section verification")
}

fn find(
    sections: &[StoredSection],
    screen: &StoredSection,
    range: Range<u64>,
) -> Result<Option<u32>> {
    let threads = thread::available_parallelism()?.get();
    eprintln!("CPU search: {threads} workers (all available logical cores)");
    let probe = SectionProbe::new(screen.descriptor.seed);
    let next = AtomicU64::new(range.start);
    let found = AtomicU64::new(UINT32_END);
    let progress = progress("CPU", range.end - range.start);
    thread::scope(|scope| {
        for _ in 0..threads {
            let (probe, next, found) = (&probe, &next, &found);
            let progress = &progress;
            let end = range.end;
            scope.spawn(move || {
                while found.load(Ordering::Relaxed) == UINT32_END {
                    let start = next.fetch_add(CHUNK, Ordering::Relaxed);
                    if start >= end {
                        break;
                    }
                    let stop = (start + CHUNK).min(end);
                    let mut value = start;
                    while value + 4 <= stop {
                        if (value - start) & 255 == 0 && found.load(Ordering::Relaxed) != UINT32_END
                        {
                            progress.inc(value - start);
                            return;
                        }
                        for (lane, cipher) in probe.ciphers(value as u32).into_iter().enumerate() {
                            let salt = (value + lane as u64) as u32;
                            if screen_matches(screen, cipher)
                                && verify_all(sections, Some(salt)).is_ok()
                            {
                                progress.inc(value - start + lane as u64 + 1);
                                found.store(salt as u64, Ordering::Relaxed);
                                return;
                            }
                        }
                        value += 4;
                    }
                    for value in value..stop {
                        if found.load(Ordering::Relaxed) != UINT32_END {
                            progress.inc(value - start);
                            return;
                        }
                        let salt = value as u32;
                        if screen_matches(screen, probe.cipher(salt))
                            && verify_all(sections, Some(salt)).is_ok()
                        {
                            progress.inc(value - start + 1);
                            found.store(value, Ordering::Relaxed);
                            return;
                        }
                    }
                    progress.inc(stop - start);
                }
            });
        }
    });
    finish_progress(&progress);
    let salt = found.load(Ordering::Relaxed);
    Ok((salt != UINT32_END).then_some(salt as u32))
}

#[cfg(test)]
#[path = "../../test/cpu_search.rs"]
mod tests;
