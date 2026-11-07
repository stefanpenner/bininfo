/*
---
why: This file hashes bytes for a signature check.
uses: bininfo
how: The signature check calls this file.
This file does not read a file header.
---
*/

//! SHA-1 and SHA-2 for one signature check.
//! Each hasher takes the bytes in order and returns the digest.

pub struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    filled: usize,
    bits: u64,
}

pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    bits: u64,
}

pub struct Sha512 {
    state: [u64; 8],
    block: [u8; 128],
    filled: usize,
    bits: u128,
    out: usize,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            block: [0; 64],
            filled: 0,
            bits: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let room = 64 - self.filled;
            let take = room.min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            self.bits = self.bits.wrapping_add((take as u64).wrapping_mul(8));
            data = &data[take..];
            if self.filled == 64 {
                compress1(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 20] {
        let bits = self.bits;
        self.update(&[0x80]);
        if self.filled > 56 {
            while self.filled < 64 {
                self.block[self.filled] = 0;
                self.filled += 1;
            }
            compress1(&mut self.state, &self.block);
            self.filled = 0;
        }
        while self.filled < 56 {
            self.block[self.filled] = 0;
            self.filled += 1;
        }
        self.block[56..64].copy_from_slice(&bits.to_be_bytes());
        compress1(&mut self.state, &self.block);
        let mut out = [0u8; 20];
        for (index, word) in self.state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            filled: 0,
            bits: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let room = 64 - self.filled;
            let take = room.min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            self.bits = self.bits.wrapping_add((take as u64).wrapping_mul(8));
            data = &data[take..];
            if self.filled == 64 {
                compress256(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.bits;
        self.update(&[0x80]);
        if self.filled > 56 {
            while self.filled < 64 {
                self.block[self.filled] = 0;
                self.filled += 1;
            }
            compress256(&mut self.state, &self.block);
            self.filled = 0;
        }
        while self.filled < 56 {
            self.block[self.filled] = 0;
            self.filled += 1;
        }
        self.block[56..64].copy_from_slice(&bits.to_be_bytes());
        compress256(&mut self.state, &self.block);
        let mut out = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Sha512 {
    pub fn sha384() -> Self {
        Self::new(
            [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            48,
        )
    }

    pub fn sha512() -> Self {
        Self::new(
            [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            64,
        )
    }

    fn new(state: [u64; 8], out: usize) -> Self {
        Self {
            state,
            block: [0; 128],
            filled: 0,
            bits: 0,
            out,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let room = 128 - self.filled;
            let take = room.min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            self.bits = self.bits.wrapping_add((take as u128).wrapping_mul(8));
            data = &data[take..];
            if self.filled == 128 {
                compress512(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        let bits = self.bits;
        self.update(&[0x80]);
        if self.filled > 112 {
            while self.filled < 128 {
                self.block[self.filled] = 0;
                self.filled += 1;
            }
            compress512(&mut self.state, &self.block);
            self.filled = 0;
        }
        while self.filled < 112 {
            self.block[self.filled] = 0;
            self.filled += 1;
        }
        self.block[112..128].copy_from_slice(&bits.to_be_bytes());
        compress512(&mut self.state, &self.block);
        let mut out = vec![0u8; self.out];
        for (index, word) in self.state.iter().enumerate() {
            let start = index * 8;
            if start >= self.out {
                break;
            }
            let end = (start + 8).min(self.out);
            let bytes = word.to_be_bytes();
            out[start..end].copy_from_slice(&bytes[..end - start]);
        }
        out
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finish()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha512::sha384();
    hasher.update(data);
    let dig = hasher.finish();
    let mut out = [0u8; 48];
    out.copy_from_slice(&dig);
    out
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::sha512();
    hasher.update(data);
    let dig = hasher.finish();
    let mut out = [0u8; 64];
    out.copy_from_slice(&dig);
    out
}

fn compress1(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for index in 0..16 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&block[index * 4..index * 4 + 4]);
        w[index] = u32::from_be_bytes(bytes);
    }
    for index in 16..80 {
        w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    for index in 0..80 {
        let (f, k) = match index {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[index]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for index in 0..16 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&block[index * 4..index * 4 + 4]);
        w[index] = u32::from_be_bytes(bytes);
    }
    for index in 16..64 {
        let s0 =
            w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 =
            w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[index])
            .wrapping_add(w[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for index in 0..16 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&block[index * 8..index * 8 + 8]);
        w[index] = u64::from_be_bytes(bytes);
    }
    for index in 16..80 {
        let s0 =
            w[index - 15].rotate_right(1) ^ w[index - 15].rotate_right(8) ^ (w[index - 15] >> 7);
        let s1 =
            w[index - 2].rotate_right(19) ^ w[index - 2].rotate_right(61) ^ (w[index - 2] >> 6);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for index in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[index])
            .wrapping_add(w[index]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_digests() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn a_split_update_matches_one_call() {
        let mut hasher = Sha256::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        assert_eq!(hasher.finish(), sha256(b"abc"));
    }
}
