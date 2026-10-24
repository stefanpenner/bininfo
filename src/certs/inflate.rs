/*
---
why: This file inflates gzip and zlib streams for the certificate scan.
uses: bininfo
how: The certificate scan calls this file on a bounded input.
The output stops at a fixed cap.
---
*/

//! Inflate a raw deflate stream, a gzip member, or a zlib stream.
//! The output stops at a caller cap.
//! A zlib preset dictionary is rejected.

use std::sync::OnceLock;

const MAX_BITS: usize = 15;
const MAX_CODES: usize = 320;

/// Inflate one raw deflate stream.
/// The result is the output and the number of input bytes used.
pub(super) fn raw(input: &[u8], max_out: usize) -> Option<(Vec<u8>, usize)> {
    let (out, used, done) = run(input, max_out, true)?;
    if !done {
        return None;
    }
    Some((out, used))
}

/// Inflate at most `max_out` bytes.
/// A short result means the stream continued past the cap.
pub(super) fn prefix(input: &[u8], max_out: usize) -> Option<Vec<u8>> {
    let (out, _, _) = run(input, max_out, false)?;
    Some(out)
}

/// Inflate one gzip member.
/// The result is the output and the member length.
pub(super) fn gunzip(input: &[u8], max_out: usize) -> Option<(Vec<u8>, usize)> {
    if input.len() < 18 || input[0] != 0x1f || input[1] != 0x8b || input[2] != 8 {
        return None;
    }
    let flags = input[3];
    if flags & 0xe0 != 0 {
        return None;
    }
    let mut at = 10usize;
    if flags & 4 != 0 {
        if at + 2 > input.len() {
            return None;
        }
        let extra = u16::from_le_bytes([input[at], input[at + 1]]) as usize;
        at = at.checked_add(2)?.checked_add(extra)?;
    }
    if flags & 8 != 0 {
        let end = input[at..].iter().position(|byte| *byte == 0)?;
        at = at.checked_add(end)?.checked_add(1)?;
    }
    if flags & 16 != 0 {
        let end = input[at..].iter().position(|byte| *byte == 0)?;
        at = at.checked_add(end)?.checked_add(1)?;
    }
    if flags & 2 != 0 {
        at = at.checked_add(2)?;
    }
    if at >= input.len() {
        return None;
    }
    let (out, used) = raw(&input[at..], max_out)?;
    let trailer = at.checked_add(used)?;
    if trailer.checked_add(8)? > input.len() {
        return None;
    }
    let crc = u32::from_le_bytes(input[trailer..trailer + 4].try_into().ok()?);
    let size = u32::from_le_bytes(input[trailer + 4..trailer + 8].try_into().ok()?);
    if crc != crc32(&out) || size != out.len() as u32 {
        return None;
    }
    Some((out, trailer + 8))
}

/// Inflate one zlib stream.
/// The result is the output and the stream length.
pub(super) fn unzlib(input: &[u8], max_out: usize) -> Option<(Vec<u8>, usize)> {
    if input.len() < 6 {
        return None;
    }
    let cmf = input[0];
    let flg = input[1];
    if (u16::from(cmf) * 256 + u16::from(flg)) % 31 != 0 {
        return None;
    }
    if cmf & 0x0f != 8 || cmf >> 4 > 7 || flg & 0x20 != 0 {
        return None;
    }
    let (out, used) = raw(&input[2..], max_out)?;
    let trailer = used.checked_add(2)?;
    if trailer.checked_add(4)? > input.len() {
        return None;
    }
    let expect = u32::from_be_bytes(input[trailer..trailer + 4].try_into().ok()?);
    if expect != adler32(&out) {
        return None;
    }
    Some((out, trailer + 4))
}

pub(super) fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub(super) fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a += u32::from(byte);
        if a >= 65521 {
            a -= 65521;
        }
        b += a;
        if b >= 65521 {
            b -= 65521;
        }
    }
    (b << 16) | a
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    nbits: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            acc: 0,
            nbits: 0,
        }
    }

    fn get(&mut self, n: u32) -> Option<u32> {
        if n == 0 {
            return Some(0);
        }
        if n > 24 {
            return None;
        }
        while self.nbits < n {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            self.acc |= u32::from(byte) << self.nbits;
            self.nbits += 8;
        }
        let value = self.acc & ((1u32 << n) - 1);
        self.acc >>= n;
        self.nbits -= n;
        Some(value)
    }

    fn align(&mut self) {
        self.acc >>= self.nbits;
        self.nbits = 0;
    }
}

struct Huff {
    counts: [u16; MAX_BITS + 1],
    symbols: [u16; MAX_CODES],
}

fn build(lengths: &[u8]) -> Option<Huff> {
    let mut tree = Huff {
        counts: [0; MAX_BITS + 1],
        symbols: [0; MAX_CODES],
    };
    if lengths.len() > MAX_CODES {
        return None;
    }
    for &len in lengths {
        if len as usize > MAX_BITS {
            return None;
        }
        tree.counts[len as usize] = tree.counts[len as usize].checked_add(1)?;
    }
    if tree.counts[0] as usize == lengths.len() {
        return Some(tree);
    }
    let mut left = 1i32;
    for len in 1..=MAX_BITS {
        left <<= 1;
        left -= i32::from(tree.counts[len]);
        if left < 0 {
            return None;
        }
    }
    let mut offs = [0u16; MAX_BITS + 1];
    for len in 1..MAX_BITS {
        offs[len + 1] = offs[len] + tree.counts[len];
    }
    for (symbol, &len) in lengths.iter().enumerate() {
        if len != 0 {
            let slot = offs[len as usize] as usize;
            tree.symbols[slot] = symbol as u16;
            offs[len as usize] += 1;
        }
    }
    Some(tree)
}

fn decode(tree: &Huff, bits: &mut Bits<'_>) -> Option<u16> {
    let mut code = 0i32;
    let mut first = 0i32;
    let mut index = 0usize;
    for len in 1..=MAX_BITS {
        code |= bits.get(1)? as i32;
        let count = i32::from(tree.counts[len]);
        if code - count < first {
            let slot = index + (code - first) as usize;
            return tree.symbols.get(slot).copied();
        }
        index += count as usize;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    None
}

fn fixed_trees() -> &'static (Huff, Huff) {
    static TREES: OnceLock<(Huff, Huff)> = OnceLock::new();
    TREES.get_or_init(|| {
        let mut lit = [0u8; 288];
        for item in &mut lit[..=143] {
            *item = 8;
        }
        for item in &mut lit[144..=255] {
            *item = 9;
        }
        for item in &mut lit[256..=279] {
            *item = 7;
        }
        for item in &mut lit[280..=287] {
            *item = 8;
        }
        let dist = [5u8; 32];
        (
            build(&lit).expect("fixed lit"),
            build(&dist).expect("fixed dist"),
        )
    })
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn run(input: &[u8], max_out: usize, strict: bool) -> Option<(Vec<u8>, usize, bool)> {
    let mut bits = Bits::new(input);
    let mut out = Vec::new();
    let mut blocks = 0u32;
    loop {
        blocks += 1;
        if blocks > 10_000 {
            return None;
        }
        let bfinal = bits.get(1)?;
        let btype = bits.get(2)?;
        let capped = match btype {
            0 => stored(&mut bits, &mut out, max_out)?,
            1 => {
                let (lit, dist) = fixed_trees();
                coded(&mut bits, lit, dist, &mut out, max_out)?
            }
            2 => dynamic(&mut bits, &mut out, max_out)?,
            _ => return None,
        };
        if capped {
            if strict {
                return None;
            }
            return Some((out, bits.pos, false));
        }
        if bfinal == 1 {
            return Some((out, bits.pos, true));
        }
    }
}

fn stored(bits: &mut Bits<'_>, out: &mut Vec<u8>, max_out: usize) -> Option<bool> {
    bits.align();
    let len = bits.get(16)? as usize;
    let nlen = bits.get(16)? as usize;
    if len != (nlen ^ 0xffff) {
        return None;
    }
    if bits.nbits != 0 {
        return None;
    }
    let end = bits.pos.checked_add(len)?;
    let data = bits.data.get(bits.pos..end)?;
    bits.pos = end;
    for &byte in data {
        if out.len() >= max_out {
            return Some(true);
        }
        out.push(byte);
    }
    Some(false)
}

fn dynamic(bits: &mut Bits<'_>, out: &mut Vec<u8>, max_out: usize) -> Option<bool> {
    let nlit = bits.get(5)? as usize + 257;
    let ndist = bits.get(5)? as usize + 1;
    let nclen = bits.get(4)? as usize + 4;
    if nlit > 286 || ndist > 32 || nclen > 19 {
        return None;
    }
    let mut clen = [0u8; 19];
    for slot in CL_ORDER.iter().take(nclen) {
        clen[*slot] = bits.get(3)? as u8;
    }
    let clen_tree = build(&clen)?;
    let mut lens = vec![0u8; nlit + ndist];
    let mut index = 0usize;
    let mut prev = 0u8;
    let mut have = false;
    while index < lens.len() {
        let symbol = decode(&clen_tree, bits)?;
        if symbol < 16 {
            lens[index] = symbol as u8;
            prev = symbol as u8;
            have = true;
            index += 1;
        } else if symbol == 16 {
            if !have {
                return None;
            }
            let rep = 3 + bits.get(2)? as usize;
            if index + rep > lens.len() {
                return None;
            }
            for _ in 0..rep {
                lens[index] = prev;
                index += 1;
            }
        } else if symbol == 17 {
            let rep = 3 + bits.get(3)? as usize;
            if index + rep > lens.len() {
                return None;
            }
            index += rep;
            prev = 0;
            have = true;
        } else if symbol == 18 {
            let rep = 11 + bits.get(7)? as usize;
            if index + rep > lens.len() {
                return None;
            }
            index += rep;
            prev = 0;
            have = true;
        } else {
            return None;
        }
    }
    let lit = build(&lens[..nlit])?;
    let dist = build(&lens[nlit..])?;
    coded(bits, &lit, &dist, out, max_out)
}

fn coded(
    bits: &mut Bits<'_>,
    lit: &Huff,
    dist: &Huff,
    out: &mut Vec<u8>,
    max_out: usize,
) -> Option<bool> {
    loop {
        let symbol = decode(lit, bits)? as usize;
        if symbol < 256 {
            if out.len() >= max_out {
                return Some(true);
            }
            out.push(symbol as u8);
            continue;
        }
        if symbol == 256 {
            return Some(false);
        }
        if symbol > 285 {
            return None;
        }
        let slot = symbol - 257;
        let len = usize::from(LEN_BASE[slot]) + bits.get(u32::from(LEN_EXTRA[slot]))? as usize;
        let dist_symbol = decode(dist, bits)? as usize;
        if dist_symbol >= 30 {
            return None;
        }
        let distance = usize::from(DIST_BASE[dist_symbol])
            + bits.get(u32::from(DIST_EXTRA[dist_symbol]))? as usize;
        if distance == 0 || distance > out.len() {
            return None;
        }
        for _ in 0..len {
            if out.len() >= max_out {
                return Some(true);
            }
            let byte = out[out.len() - distance];
            out.push(byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_block_inflates() {
        let input = [0x01, 0x04, 0x00, 0xfb, 0xff, b'a', b'b', b'c', b'd'];
        let (out, used) = raw(&input, 16).unwrap();
        assert_eq!(out, b"abcd");
        assert_eq!(used, input.len());
    }

    #[test]
    fn a_gzip_member_matches_the_probe() {
        let gzip = include_bytes!("../../tests/fixtures/probe-rsa.der.gz");
        let plain = include_bytes!("../../tests/fixtures/probe-rsa.der");
        let (out, used) = gunzip(gzip, 1 << 20).unwrap();
        assert_eq!(out, plain);
        assert_eq!(used, gzip.len());
    }

    #[test]
    fn a_zlib_stored_stream_matches_adler() {
        let payload = b"abcd";
        let mut input = vec![0x78, 0x01, 0x01, 0x04, 0x00, 0xfb, 0xff];
        input.extend_from_slice(payload);
        input.extend_from_slice(&adler32(payload).to_be_bytes());
        let (out, used) = unzlib(&input, 16).unwrap();
        assert_eq!(out, payload);
        assert_eq!(used, input.len());
        input[2] ^= 0xff;
        assert!(unzlib(&input, 16).is_none());
    }

    #[test]
    fn a_cap_rejects_a_strict_stream() {
        let input = [0x01, 0x04, 0x00, 0xfb, 0xff, b'a', b'b', b'c', b'd'];
        assert!(raw(&input, 3).is_none());
        let got = prefix(&input, 3).unwrap();
        assert_eq!(got, b"abc");
    }

    #[test]
    fn crc32_matches_a_known_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
