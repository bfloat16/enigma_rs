//! Bounded translation of the Enigma LZ stream and E8/E9/FF25 inverse filter.

use anyhow::{Result, bail, ensure};

pub const MAX_EXPANDED: usize = 256 * 1024 * 1024;

pub fn expanded_size(size: usize) -> Result<usize> {
    if size == 0 || size > MAX_EXPANDED {
        bail!("invalid expanded size {size:#x} (limit {MAX_EXPANDED:#x})");
    }
    Ok(size)
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    bits: u8,
    remaining: u8,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bits: 0,
            remaining: 0,
        }
    }
    fn byte(&mut self) -> Result<u8> {
        let value = *self
            .data
            .get(self.pos)
            .ok_or_else(|| anyhow::anyhow!("truncated LZ input"))?;
        self.pos += 1;
        Ok(value)
    }
    fn bit(&mut self) -> Result<u32> {
        if self.remaining == 0 {
            self.bits = self.byte()?;
            self.remaining = 8;
        }
        let result = (self.bits >> 7) as u32;
        self.bits <<= 1;
        self.remaining -= 1;
        Ok(result)
    }
    fn gamma(&mut self) -> Result<usize> {
        let mut value = 1usize;
        for _ in 0..31 {
            value = (value << 1) | self.bit()? as usize;
            if self.bit()? == 0 {
                return Ok(value);
            }
        }
        bail!("LZ gamma code exceeds 32 bits")
    }
}

fn copy(output: &mut Vec<u8>, distance: usize, length: usize, limit: usize) -> Result<()> {
    ensure!(
        distance > 0 && distance <= output.len(),
        "invalid LZ distance {distance}"
    );
    ensure!(
        length <= limit - output.len(),
        "LZ output exceeds declared size"
    );
    for _ in 0..length {
        output.push(output[output.len() - distance]);
    }
    Ok(())
}

/// Loader streams may contain block padding; configuration/section streams are strict.
pub fn decompress(data: &[u8], expected: usize, strict: bool) -> Result<Vec<u8>> {
    expanded_size(expected)?;
    let mut input = Bits::new(data);
    let mut output = Vec::with_capacity(expected);
    output.push(input.byte()?);
    let mut lwm = 2usize;
    let mut previous = 0;
    loop {
        if input.bit()? == 0 {
            ensure!(output.len() < expected, "LZ literal exceeds declared size");
            output.push(input.byte()?);
            lwm = 2;
        } else if input.bit()? == 0 {
            let code = input.gamma()?;
            ensure!(code >= lwm, "negative LZ distance code");
            let distance_code = code - lwm;
            lwm = 1;
            if distance_code == 0 {
                let length = input.gamma()?;
                copy(&mut output, previous, length, expected)?;
            } else {
                let distance = ((distance_code - 1) << 8) | input.byte()? as usize;
                let length = input.gamma()?
                    + usize::from(distance >= 0x7d00)
                    + usize::from(distance >= 0x500)
                    + 2 * usize::from(distance < 0x80);
                copy(&mut output, distance, length, expected)?;
                previous = distance;
            }
        } else if input.bit()? == 0 {
            let value = input.byte()? as usize;
            let distance = value >> 1;
            if distance == 0 {
                ensure!(
                    output.len() == expected,
                    "LZ expanded size mismatch: {} != {expected}",
                    output.len()
                );
                ensure!(
                    !strict || input.pos == data.len(),
                    "unconsumed bytes after LZ terminator"
                );
                return Ok(output);
            }
            copy(&mut output, distance, 2 + (value & 1), expected)?;
            previous = distance;
            lwm = 1;
        } else {
            let mut distance = 0;
            for _ in 0..4 {
                distance = (distance << 1) | input.bit()? as usize;
            }
            if distance == 0 {
                ensure!(
                    output.len() < expected,
                    "LZ zero literal exceeds declared size"
                );
                output.push(0);
            } else {
                copy(&mut output, distance, 1, expected)?;
            }
            lwm = 2;
        }
    }
}

pub fn fix_branches(data: &mut [u8]) {
    let mut pos = 0usize;
    let mut counter = 0u32;
    // Preserve the original loop's remaining > 1 after subtracting five.
    while pos + 6 < data.len() {
        if data[pos] == 0xe8 || data[pos] == 0xe9 {
            let old = u32::from_le_bytes(data[pos + 1..pos + 5].try_into().unwrap());
            data[pos + 1..pos + 5].copy_from_slice(&old.wrapping_sub(pos as u32).to_le_bytes());
            pos += 5;
        } else if data[pos..pos + 2] == [0xff, 0x25] {
            let old = u32::from_le_bytes(data[pos + 2..pos + 6].try_into().unwrap());
            data[pos + 2..pos + 6].copy_from_slice(&old.wrapping_sub(counter).to_le_bytes());
            counter = counter.wrapping_sub(4);
            pos += 6;
        } else {
            pos += 1;
        }
    }
}

/// Reject structurally impossible LZ prefixes without expanding data. Exhausting
/// a prefix is inconclusive, never a rejection. Used only as a salt prefilter.
pub fn plausible_prefix(data: &[u8], packed_size: usize, expected: usize) -> bool {
    fn check(data: &[u8], packed_size: usize, expected: usize) -> Option<bool> {
        let mut input = Bits::new(data);
        input.byte().ok()?;
        let (mut size, mut lwm, mut previous) = (1usize, 2usize, 0usize);
        loop {
            let (distance, length);
            if input.bit().ok()? == 0 {
                input.byte().ok()?;
                size += 1;
                lwm = 2;
                if size > expected {
                    return Some(false);
                }
                continue;
            } else if input.bit().ok()? == 0 {
                let code = input.gamma().ok()?;
                if code < lwm {
                    return Some(false);
                }
                let d = code - lwm;
                lwm = 1;
                if d == 0 {
                    distance = previous;
                    length = input.gamma().ok()?;
                } else {
                    distance = ((d - 1) << 8) | input.byte().ok()? as usize;
                    length = input.gamma().ok()?
                        + usize::from(distance >= 0x7d00)
                        + usize::from(distance >= 0x500)
                        + 2 * usize::from(distance < 0x80);
                    previous = distance;
                }
            } else if input.bit().ok()? == 0 {
                let value = input.byte().ok()? as usize;
                distance = value >> 1;
                length = 2 + (value & 1);
                if distance == 0 {
                    return Some(size == expected && input.pos == packed_size);
                }
                previous = distance;
                lwm = 1;
            } else {
                let mut d = 0;
                for _ in 0..4 {
                    d = (d << 1) | input.bit().ok()? as usize;
                }
                if d == 0 {
                    size += 1;
                    lwm = 2;
                    if size > expected {
                        return Some(false);
                    }
                    continue;
                }
                distance = d;
                length = 1;
                lwm = 2;
            }
            if distance == 0 || distance > size || length > expected.saturating_sub(size) {
                return Some(false);
            }
            size += length;
        }
    }
    check(data, packed_size, expected).unwrap_or(true)
}
