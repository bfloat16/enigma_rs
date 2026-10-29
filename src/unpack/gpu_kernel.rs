//! Shared CubeCL CUDA/WGPU MD5/RC4/LZ-prefix/CRC32 kernel.
use super::{
    extract::{StoredSection, verify_all},
    search::{UINT32_END, finish_progress, progress},
};
use anyhow::{Context, Result, ensure};
use cubecl::prelude::*;

const LANES: u32 = 128;
const BATCH: u64 = 4_194_304;

/// A reusable uploaded probe; public for explicit hardware conformance tests.
pub struct GpuProbe<R: Runtime> {
    client: ComputeClient<R>,
    cipher: cubecl::server::Handle,
    parameters: cubecl::server::Handle,
    table: cubecl::server::Handle,
    hits: cubecl::server::Handle,
    length: usize,
    expected: u32,
    crc: u32,
    compressed: u32,
}

impl<R: Runtime> GpuProbe<R> {
    pub(crate) fn new(section: &StoredSection, client: ComputeClient<R>) -> Result<Self> {
        ensure!(!section.ciphertext.is_empty(), "empty GPU probe");
        ensure!(
            section.descriptor.flags & 8 != 0
                && section.ciphertext.len() == section.descriptor.packed_size,
            "GPU probe requires an RC4 section with matching stored length"
        );
        crate::common::codec::expanded_size(section.ciphertext.len())?;
        crate::common::codec::expanded_size(section.descriptor.expanded_size)?;
        let cipher: Vec<u32> = section.ciphertext.iter().map(|&b| b as u32).collect();
        let seed = section.descriptor.seed;
        let mut initial: Vec<u32> = (0..256).collect();
        let mut j = 0;
        for i in 0..16 {
            j = (j + initial[i] + seed[i] as u32) & 255;
            initial.swap(i, j as usize);
        }
        let mut parameters: Vec<u32> = seed.iter().map(|&b| b as u32).collect();
        parameters.push(j);
        parameters.extend(
            initial
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)),
        );
        let table: Vec<u32> = (0..256u32)
            .map(|mut c| {
                for _ in 0..8 {
                    c = (c >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(c & 1));
                }
                c
            })
            .collect();
        Ok(Self {
            cipher: client.create_from_slice(u32::as_bytes(&cipher)),
            parameters: client.create_from_slice(u32::as_bytes(&parameters)),
            table: client.create_from_slice(u32::as_bytes(&table)),
            hits: client.empty(BATCH as usize * 4),
            client,
            length: cipher.len(),
            expected: u32::try_from(section.descriptor.expanded_size)?,
            crc: section.descriptor.crc32,
            compressed: section.descriptor.flags & 1,
        })
    }

    /// Returns every CRC hit, including salt zero and u32::MAX. There is no
    /// fixed-size candidate list that could overflow and silently lose hits.
    pub fn scan(&mut self, start: u64, end: u64) -> Result<Vec<u32>> {
        ensure!(
            start < end && end <= UINT32_END && end - start <= BATCH,
            "invalid GPU batch"
        );
        let count = (end - start) as u32;
        let hit_count = self.client.create_from_slice(u32::as_bytes(&[0]));
        // Each hit reserves one slot. At most `count` lanes can hit, so the
        // candidate buffer cannot overflow, including a hit for every lane.
        unsafe {
            enumerate::launch_unchecked::<R>(
                &self.client,
                CubeCount::Static(count.div_ceil(LANES), 1, 1),
                CubeDim::new_1d(LANES),
                ArrayArg::from_raw_parts(self.cipher.clone(), self.length),
                ArrayArg::from_raw_parts(self.parameters.clone(), 81),
                ArrayArg::from_raw_parts(self.table.clone(), 256),
                ArrayArg::from_raw_parts(self.hits.clone(), count as usize),
                ArrayArg::from_raw_parts(hit_count.clone(), 1),
                start as u32,
                count,
                self.expected,
                self.crc,
                self.compressed,
            );
        }
        // Read only the counter for batches without hits.
        let bytes = self
            .client
            .read_one(hit_count)
            .context("read GPU hit count")?;
        let count = u32::from_bytes(&bytes)[0] as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let bytes = self
            .client
            .read_one(self.hits.clone())
            .context("read GPU candidates")?;
        let mut hits = u32::from_bytes(&bytes)[..count].to_vec();
        hits.sort_unstable();
        Ok(hits)
    }
}

pub(crate) fn search<R: Runtime>(
    backend: &'static str,
    sections: &[StoredSection],
    mut probe: GpuProbe<R>,
) -> Result<Option<u32>> {
    let progress = progress(backend, UINT32_END);
    for start in (0..UINT32_END).step_by(BATCH as usize) {
        let end = (start + BATCH).min(UINT32_END);
        let hits = probe.scan(start, end)?;
        progress.inc(end - start);
        for salt in hits {
            if verify_all(sections, Some(salt)).is_ok() {
                finish_progress(&progress);
                return Ok(Some(salt));
            }
        }
    }
    finish_progress(&progress);
    Ok(None)
}

#[derive(CubeType)]
struct PrefixBits {
    pos: u32,
    bits: u32,
    remaining: u32,
    exhausted: bool,
}

#[cube]
impl PrefixBits {
    fn byte(&mut self, data: &Array<u32>, length: u32) -> u32 {
        let mut value = 0u32;
        if self.pos < length {
            value = data[self.pos as usize];
            self.pos += 1;
        } else {
            self.exhausted = true;
        }
        value
    }

    fn bit(&mut self, data: &Array<u32>, length: u32) -> u32 {
        if self.remaining == 0 {
            self.bits = self.byte(data, length);
            self.remaining = 8;
        }
        let value = (self.bits >> 7) & 1;
        self.bits <<= 1;
        self.remaining -= 1;
        value
    }

    fn gamma(&mut self, data: &Array<u32>, length: u32) -> u32 {
        let mut value = 1u32;
        let mut done: bool = false;
        let mut rounds: u32 = 0;
        while rounds < 31 && !done {
            value = (value << 1) | self.bit(data, length);
            rounds += 1;
            if self.bit(data, length) == 0 || self.exhausted {
                done = true;
            }
        }
        if !done {
            // Like the CPU prefilter, an overlong gamma prefix is inconclusive.
            self.exhausted = true;
        }
        value
    }
}

#[cube]
fn plausible(data: &Array<u32>, length: u32, packed: u32, expected: u32) -> bool {
    let mut input = PrefixBits {
        pos: 1,
        bits: 0,
        remaining: 0,
        exhausted: false,
    };
    let mut size = 1u32;
    let mut lwm = 2u32;
    let mut previous = 0u32;
    let mut status: u32 = 0;
    while status == 0 {
        let mut distance = 0u32;
        let mut count = 0u32;
        let mut valid = true;
        let mut literal = false;
        if input.bit(data, length) == 0 {
            input.byte(data, length);
            count = 1;
            lwm = 2;
            literal = true;
        } else if input.bit(data, length) == 0 {
            let code = input.gamma(data, length);
            if code < lwm {
                valid = false;
            } else {
                let d = code - lwm;
                if d == 0 {
                    distance = previous;
                    count = input.gamma(data, length);
                } else {
                    // Output objects are bounded to 256 MiB on the host. Codes
                    // beyond this bound cannot be a valid backwards distance.
                    // Still consume the prefix: exhaustion is inconclusive.
                    if d > 0x100001 {
                        valid = false;
                    }
                    distance = ((d - 1) << 8) | input.byte(data, length);
                    count = input.gamma(data, length);
                    if count > expected {
                        valid = false;
                        count = 0;
                    }
                    if distance >= 0x7d00 {
                        count += 1;
                    }
                    if distance >= 0x500 {
                        count += 1;
                    }
                    if distance < 0x80 {
                        count += 2;
                    }
                    previous = distance;
                }
            }
            lwm = 1;
        } else if input.bit(data, length) == 0 {
            let value = input.byte(data, length);
            distance = value >> 1;
            count = 2 + (value & 1);
            if distance == 0 {
                if size == expected && input.pos == packed {
                    status = 1;
                } else {
                    status = 2;
                }
            }
            previous = distance;
            lwm = 1;
        } else {
            for _ in 0..4 {
                distance = (distance << 1) | input.bit(data, length);
            }
            count = 1;
            literal = distance == 0;
            lwm = 2;
        }
        if input.exhausted {
            status = 1;
        } else if status == 0
            && (!valid
                || count > expected - u32::min(size, expected)
                || (!literal && (distance == 0 || distance > size)))
        {
            status = 2;
        }
        if status == 0 {
            size += count;
        }
    }
    status == 1
}

#[allow(clippy::manual_rotate)] // CubeCL has no rotate_left primitive.
#[cube]
fn md5_step(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    m: u32,
    #[comptime] k: u32,
    #[comptime] shift: u32,
    #[comptime] round: u32,
) -> u32 {
    let f = if round == 0 {
        (b & c) | (!b & d)
    } else if round == 1 {
        (d & b) | (!d & c)
    } else if round == 2 {
        b ^ c ^ d
    } else {
        c ^ (b | !d)
    };
    let x = a + f + m + k;
    b + ((x << shift) | (x >> (32u32 - shift)))
}

#[cube]
fn md5_four_bytes(salt: u32) -> Array<u32> {
    let mut a = 0x67452301u32;
    let mut b = 0xefcdab89u32;
    let mut c = 0x98badcfeu32;
    let mut d = 0x10325476u32;
    a = md5_step(a, b, c, d, salt, 0xd76aa478u32, 7u32, 0u32);
    d = md5_step(d, a, b, c, 0x80u32, 0xe8c7b756u32, 12u32, 0u32);
    c = md5_step(c, d, a, b, 0u32, 0x242070dbu32, 17u32, 0u32);
    b = md5_step(b, c, d, a, 0u32, 0xc1bdceeeu32, 22u32, 0u32);
    a = md5_step(a, b, c, d, 0u32, 0xf57c0fafu32, 7u32, 0u32);
    d = md5_step(d, a, b, c, 0u32, 0x4787c62au32, 12u32, 0u32);
    c = md5_step(c, d, a, b, 0u32, 0xa8304613u32, 17u32, 0u32);
    b = md5_step(b, c, d, a, 0u32, 0xfd469501u32, 22u32, 0u32);
    a = md5_step(a, b, c, d, 0u32, 0x698098d8u32, 7u32, 0u32);
    d = md5_step(d, a, b, c, 0u32, 0x8b44f7afu32, 12u32, 0u32);
    c = md5_step(c, d, a, b, 0u32, 0xffff5bb1u32, 17u32, 0u32);
    b = md5_step(b, c, d, a, 0u32, 0x895cd7beu32, 22u32, 0u32);
    a = md5_step(a, b, c, d, 0u32, 0x6b901122u32, 7u32, 0u32);
    d = md5_step(d, a, b, c, 0u32, 0xfd987193u32, 12u32, 0u32);
    c = md5_step(c, d, a, b, 32u32, 0xa679438eu32, 17u32, 0u32);
    b = md5_step(b, c, d, a, 0u32, 0x49b40821u32, 22u32, 0u32);
    a = md5_step(a, b, c, d, 0x80u32, 0xf61e2562u32, 5u32, 1u32);
    d = md5_step(d, a, b, c, 0u32, 0xc040b340u32, 9u32, 1u32);
    c = md5_step(c, d, a, b, 0u32, 0x265e5a51u32, 14u32, 1u32);
    b = md5_step(b, c, d, a, salt, 0xe9b6c7aau32, 20u32, 1u32);
    a = md5_step(a, b, c, d, 0u32, 0xd62f105du32, 5u32, 1u32);
    d = md5_step(d, a, b, c, 0u32, 0x02441453u32, 9u32, 1u32);
    c = md5_step(c, d, a, b, 0u32, 0xd8a1e681u32, 14u32, 1u32);
    b = md5_step(b, c, d, a, 0u32, 0xe7d3fbc8u32, 20u32, 1u32);
    a = md5_step(a, b, c, d, 0u32, 0x21e1cde6u32, 5u32, 1u32);
    d = md5_step(d, a, b, c, 32u32, 0xc33707d6u32, 9u32, 1u32);
    c = md5_step(c, d, a, b, 0u32, 0xf4d50d87u32, 14u32, 1u32);
    b = md5_step(b, c, d, a, 0u32, 0x455a14edu32, 20u32, 1u32);
    a = md5_step(a, b, c, d, 0u32, 0xa9e3e905u32, 5u32, 1u32);
    d = md5_step(d, a, b, c, 0u32, 0xfcefa3f8u32, 9u32, 1u32);
    c = md5_step(c, d, a, b, 0u32, 0x676f02d9u32, 14u32, 1u32);
    b = md5_step(b, c, d, a, 0u32, 0x8d2a4c8au32, 20u32, 1u32);
    a = md5_step(a, b, c, d, 0u32, 0xfffa3942u32, 4u32, 2u32);
    d = md5_step(d, a, b, c, 0u32, 0x8771f681u32, 11u32, 2u32);
    c = md5_step(c, d, a, b, 0u32, 0x6d9d6122u32, 16u32, 2u32);
    b = md5_step(b, c, d, a, 32u32, 0xfde5380cu32, 23u32, 2u32);
    a = md5_step(a, b, c, d, 0x80u32, 0xa4beea44u32, 4u32, 2u32);
    d = md5_step(d, a, b, c, 0u32, 0x4bdecfa9u32, 11u32, 2u32);
    c = md5_step(c, d, a, b, 0u32, 0xf6bb4b60u32, 16u32, 2u32);
    b = md5_step(b, c, d, a, 0u32, 0xbebfbc70u32, 23u32, 2u32);
    a = md5_step(a, b, c, d, 0u32, 0x289b7ec6u32, 4u32, 2u32);
    d = md5_step(d, a, b, c, salt, 0xeaa127fau32, 11u32, 2u32);
    c = md5_step(c, d, a, b, 0u32, 0xd4ef3085u32, 16u32, 2u32);
    b = md5_step(b, c, d, a, 0u32, 0x04881d05u32, 23u32, 2u32);
    a = md5_step(a, b, c, d, 0u32, 0xd9d4d039u32, 4u32, 2u32);
    d = md5_step(d, a, b, c, 0u32, 0xe6db99e5u32, 11u32, 2u32);
    c = md5_step(c, d, a, b, 0u32, 0x1fa27cf8u32, 16u32, 2u32);
    b = md5_step(b, c, d, a, 0u32, 0xc4ac5665u32, 23u32, 2u32);
    a = md5_step(a, b, c, d, salt, 0xf4292244u32, 6u32, 3u32);
    d = md5_step(d, a, b, c, 0u32, 0x432aff97u32, 10u32, 3u32);
    c = md5_step(c, d, a, b, 32u32, 0xab9423a7u32, 15u32, 3u32);
    b = md5_step(b, c, d, a, 0u32, 0xfc93a039u32, 21u32, 3u32);
    a = md5_step(a, b, c, d, 0u32, 0x655b59c3u32, 6u32, 3u32);
    d = md5_step(d, a, b, c, 0u32, 0x8f0ccc92u32, 10u32, 3u32);
    c = md5_step(c, d, a, b, 0u32, 0xffeff47du32, 15u32, 3u32);
    b = md5_step(b, c, d, a, 0x80u32, 0x85845dd1u32, 21u32, 3u32);
    a = md5_step(a, b, c, d, 0u32, 0x6fa87e4fu32, 6u32, 3u32);
    d = md5_step(d, a, b, c, 0u32, 0xfe2ce6e0u32, 10u32, 3u32);
    c = md5_step(c, d, a, b, 0u32, 0xa3014314u32, 15u32, 3u32);
    b = md5_step(b, c, d, a, 0u32, 0x4e0811a1u32, 21u32, 3u32);
    a = md5_step(a, b, c, d, 0u32, 0xf7537e82u32, 6u32, 3u32);
    d = md5_step(d, a, b, c, 0u32, 0xbd3af235u32, 10u32, 3u32);
    c = md5_step(c, d, a, b, 0u32, 0x2ad7d2bbu32, 15u32, 3u32);
    b = md5_step(b, c, d, a, 0u32, 0xeb86d391u32, 21u32, 3u32);
    let mut out = Array::<u32>::new(4usize);
    out[0usize] = a + 0x67452301u32;
    out[1usize] = b + 0xefcdab89u32;
    out[2usize] = c + 0x98badcfeu32;
    out[3usize] = d + 0x10325476u32;
    out
}

// Four RC4 bytes per shared-memory word, interleaved by lane. Every lane owns
// its words, and all 32 lanes of a warp use different banks even for random S[i].
// This avoids spilling 256 dynamically indexed private words to device memory.
#[cube]
fn state_read(state: &SharedMemory<u32>, index: u32) -> u32 {
    let word = ((index >> 2) as usize) * 128usize + UNIT_POS_X as usize;
    (state[word] >> ((index & 3) * 8)) & 255
}

#[cube]
fn state_write(state: &mut SharedMemory<u32>, index: u32, value: u32) {
    let word = ((index >> 2) as usize) * 128usize + UNIT_POS_X as usize;
    let shift = (index & 3) * 8;
    state[word] = (state[word] & !(255u32 << shift)) | (value << shift);
}

#[cube]
fn rc4_byte(state: &mut SharedMemory<u32>, i: u32, j: u32, cipher: u32) -> (u32, u32) {
    let a = state_read(state, i);
    let next_j = (j + a) & 255;
    let b = state_read(state, next_j);
    state_write(state, i, b);
    state_write(state, next_j, a);
    (cipher ^ state_read(state, (a + b) & 255), next_j)
}

#[cube]
fn crc_byte(crc: u32, value: u32, table: &Array<u32>) -> u32 {
    (crc >> 8) ^ table[((crc ^ value) & 255) as usize]
}

#[cube(launch_unchecked)]
pub(crate) fn enumerate(
    cipher: &Array<u32>,
    parameters: &Array<u32>,
    table: &Array<u32>,
    hits: &mut Array<u32>,
    hit_count: &Array<Atomic<u32>>,
    start: u32,
    count: u32,
    expected: u32,
    expected_crc: u32,
    compressed: u32,
) {
    let at = ABSOLUTE_POS as u32;
    if at < count {
        let salt = start + at;
        let digest = md5_four_bytes(salt);
        let mut state = SharedMemory::<u32>::new(8192usize);
        for i in 0..64usize {
            state[i * 128usize + UNIT_POS_X as usize] = parameters[17usize + i];
        }
        let mut j = parameters[16usize];
        for i in 16..256u32 {
            let k = i & 31;
            let key = if k < 16 {
                parameters[k as usize]
            } else {
                (digest[((k - 16) >> 2) as usize] >> ((k & 3) * 8)) & 255
            };
            let a = state_read(&state, i);
            j = (j + a + key) & 255;
            let b = state_read(&state, j);
            state_write(&mut state, i, b);
            state_write(&mut state, j, a);
        }
        let packed = cipher.len() as u32;
        let length = u32::min(packed, 64);
        let first = u32::min(length, 8);
        let mut prefix = Array::<u32>::new(64usize);
        j = 0;
        for pos in 0..first {
            let pair = rc4_byte(&mut state, (pos + 1) & 255, j, cipher[pos as usize]);
            j = pair.1;
            prefix[pos as usize] = pair.0;
        }
        if compressed != 0 && !plausible(&prefix, first, packed, expected) {
            terminate!();
        }
        for pos in first..length {
            let pair = rc4_byte(&mut state, (pos + 1) & 255, j, cipher[pos as usize]);
            j = pair.1;
            prefix[pos as usize] = pair.0;
        }
        if compressed == 0 || plausible(&prefix, length, packed, expected) {
            // CRC is useful only after the structural filter has accepted.
            let mut crc = 0xffffffffu32;
            for pos in 0..length {
                crc = crc_byte(crc, prefix[pos as usize], table);
            }
            for pos in length..packed {
                let pair = rc4_byte(&mut state, (pos + 1) & 255, j, cipher[pos as usize]);
                j = pair.1;
                crc = crc_byte(crc, pair.0, table);
            }
            if (crc ^ 0xffffffffu32) == expected_crc {
                let slot = hit_count[0].fetch_add(1);
                hits[slot as usize] = salt;
            }
        }
    }
}
