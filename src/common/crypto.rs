//! RC4 shared by configuration decoding (16 bytes) and sections (16/32 bytes).

pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key cannot be empty");
        let mut state = std::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Self { state, i: 0, j: 0 }
    }

    #[inline(always)]
    pub fn byte(&mut self, byte: u8) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        let at = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
        byte ^ self.state[at as usize]
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.byte(*byte);
        }
    }
}

pub fn decipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    Rc4::new(key).apply(&mut result);
    result
}

pub fn section_key(seed: &[u8; 16], salt: u32) -> [u8; 32] {
    let mut key = [0; 32];
    key[..16].copy_from_slice(seed);
    key[16..].copy_from_slice(&md5::compute(salt.to_le_bytes()).0);
    key
}

/// The first 16 KSA rounds depend only on the seed. Reuse them for every salt.
pub struct SectionProbe {
    initial: [u8; 256],
    initial_j: u8,
    seed: [u8; 16],
}

impl SectionProbe {
    pub fn new(seed: [u8; 16]) -> Self {
        let mut state = std::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..16 {
            j = j.wrapping_add(state[i]).wrapping_add(seed[i]);
            state.swap(i, j as usize);
        }
        Self {
            initial: state,
            initial_j: j,
            seed,
        }
    }

    #[inline]
    pub fn cipher(&self, salt: u32) -> Rc4 {
        let key = section_key(&self.seed, salt);
        let mut state = self.initial;
        let mut j = self.initial_j;
        for i in 16..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i & 31]);
            state.swap(i, j as usize);
        }
        Rc4 { state, i: 0, j: 0 }
    }

    /// Interleave independent KSA chains so the CPU can overlap indexed loads.
    pub(crate) fn ciphers(&self, start: u32) -> [Rc4; 4] {
        let keys: [_; 4] = std::array::from_fn(|n| section_key(&self.seed, start + n as u32));
        let mut states = [self.initial; 4];
        let mut js = [self.initial_j; 4];
        for i in 16..256 {
            for lane in 0..4 {
                let state = &mut states[lane];
                js[lane] = js[lane]
                    .wrapping_add(state[i])
                    .wrapping_add(keys[lane][i & 31]);
                state.swap(i, js[lane] as usize);
            }
        }
        states.map(|state| Rc4 { state, i: 0, j: 0 })
    }
}
