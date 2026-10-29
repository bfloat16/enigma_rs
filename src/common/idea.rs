//! IDEA with the Loader's CBC feedback and unpadded partial-block tail.

pub struct Idea {
    enc: [u16; 52],
    dec: [u16; 52],
}

fn mul(a: u16, b: u16) -> u16 {
    let a = if a == 0 { 65536 } else { a as u64 };
    let b = if b == 0 { 65536 } else { b as u64 };
    ((a * b) % 65537) as u16
}

fn inverse(a: u16) -> u16 {
    // Fermat's theorem in the prime field, including IDEA's encoded zero.
    let (mut base, mut exponent, mut result) = (a, 65535u32, 1);
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }
    result
}

fn block(input: &[u8; 8], k: &[u16; 52]) -> [u8; 8] {
    let mut x: [u16; 4] =
        std::array::from_fn(|i| u16::from_be_bytes([input[i * 2], input[i * 2 + 1]]));
    for round in 0..8 {
        let p = round * 6;
        x[0] = mul(x[0], k[p]);
        x[1] = x[1].wrapping_add(k[p + 1]);
        x[2] = x[2].wrapping_add(k[p + 2]);
        x[3] = mul(x[3], k[p + 3]);
        let a = mul(k[p + 4], x[0] ^ x[2]);
        let b = mul(k[p + 5], (x[1] ^ x[3]).wrapping_add(a));
        let c = a.wrapping_add(b);
        x = [x[0] ^ b, x[2] ^ b, x[1] ^ c, x[3] ^ c];
    }
    let y = [
        mul(x[0], k[48]),
        x[2].wrapping_add(k[49]),
        x[1].wrapping_add(k[50]),
        mul(x[3], k[51]),
    ];
    let mut out = [0; 8];
    for (chunk, value) in out.as_chunks_mut::<2>().0.iter_mut().zip(y) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    out
}

impl Idea {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut enc = [0; 52];
        let mut state = u128::from_be_bytes(*key);
        for (i, word) in enc.iter_mut().enumerate() {
            if i > 0 && i % 8 == 0 {
                state = state.rotate_left(25);
            }
            *word = (state >> (112 - (i % 8) * 16)) as u16;
        }
        let mut dec = [0; 52];
        for round in 0..9 {
            let p = round * 6;
            let s = 48 - round * 6;
            dec[p] = inverse(enc[s]);
            dec[p + 1] = enc[s + if round == 0 || round == 8 { 1 } else { 2 }].wrapping_neg();
            dec[p + 2] = enc[s + if round == 0 || round == 8 { 2 } else { 1 }].wrapping_neg();
            dec[p + 3] = inverse(enc[s + 3]);
            if round < 8 {
                dec[p + 4] = enc[46 - round * 6];
                dec[p + 5] = enc[47 - round * 6];
            }
        }
        Self { enc, dec }
    }

    pub fn encrypt_block(&self, data: &[u8; 8]) -> [u8; 8] {
        block(data, &self.enc)
    }
    pub fn decrypt_block(&self, data: &[u8; 8]) -> [u8; 8] {
        block(data, &self.dec)
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut feedback = self.encrypt_block(&[0; 8]);
        let mut output = Vec::with_capacity(data.len());
        for chunk in data.chunks(8) {
            if let Ok(cipher) = <&[u8; 8]>::try_from(chunk) {
                output.extend(
                    self.decrypt_block(cipher)
                        .iter()
                        .zip(feedback)
                        .map(|(a, b)| a ^ b),
                );
                feedback = *cipher;
            } else {
                output.extend(
                    chunk
                        .iter()
                        .zip(self.encrypt_block(&feedback))
                        .map(|(a, b)| a ^ b),
                );
            }
        }
        output
    }
}
