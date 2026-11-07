/*
---
why: This file reads one MPQ archive header and its block table.
uses: bininfo
how: bininfo calls this file when the bytes start with MPQ.
This file decrypts the block table.
This file does not decrypt a stored file.
---
*/

//! One MPQ archive. The header names the hash table and the block table.
//! This module decrypts those tables. It does not decrypt a stored file.

pub mod page;

const BLOCK_CAP: usize = 256;
const EXISTS: u32 = 0x8000_0000;
const IMPLODE: u32 = 0x0000_0100;
const COMPRESS: u32 = 0x0000_0200;
const ENCRYPTED: u32 = 0x0001_0000;

/// One block-table row. `offset` is a byte offset in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub offset: u64,
    pub stored: u64,
    pub size: u64,
    pub flags: u32,
}

/// One MPQ archive. Counts cover every block. `blocks` keeps the first rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    pub version: u16,
    pub header_size: u32,
    pub archive_size: u64,
    pub sector: u64,
    pub hash_offset: u64,
    pub hash_count: u32,
    pub block_offset: u64,
    pub block_count: u32,
    pub files: u64,
    pub compressed: u64,
    pub encrypted: u64,
    pub blocks: Vec<Block>,
    pub more: u64,
}

/// True when the bytes start with an MPQ header or an MPQ user-data header.
pub fn is_mpq(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MPQ\x1a") || bytes.starts_with(b"MPQ\x1b")
}

/// Read the header and the block table.
/// A user-data header points at the real header. This function does not search the file.
pub fn parse(bytes: &[u8]) -> Result<Archive, String> {
    let base = header_base(bytes)?;
    if bytes.get(base..base.saturating_add(4)) != Some(&b"MPQ\x1a"[..]) {
        return Err("mpq header is missing".into());
    }
    let header_size = u32_at(bytes, base + 4)?;
    if header_size < 32 {
        return Err("mpq header is short".into());
    }
    let mut archive_size = u64::from(u32_at(bytes, base + 8)?);
    let version = u16_at(bytes, base + 12)?;
    let shift = u16_at(bytes, base + 14)?;
    let sector = 512u64
        .checked_shl(u32::from(shift))
        .ok_or("sector shift is too large")?;
    let hash_low = u32_at(bytes, base + 16)?;
    let block_low = u32_at(bytes, base + 20)?;
    let hash_count = u32_at(bytes, base + 24)?;
    let block_count = u32_at(bytes, base + 28)?;
    let (hash_hi, block_hi) = high_pos(bytes, base, version, header_size)?;
    if version >= 2 && header_size >= 0x34 {
        archive_size = u64_at(bytes, base + 0x2C)?;
    }
    let base_at = u64::try_from(base).map_err(|_| "mpq header is past the end".to_string())?;
    let hash_offset = base_at
        .checked_add(u64::from(hash_low) | (u64::from(hash_hi) << 32))
        .ok_or("table is too large")?;
    let block_offset = base_at
        .checked_add(u64::from(block_low) | (u64::from(block_hi) << 32))
        .ok_or("table is too large")?;
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    table_fits(hash_offset, hash_count, len)?;
    table_fits(block_offset, block_count, len)?;
    let (files, compressed, encrypted, blocks, more) =
        read_blocks(bytes, base_at, block_offset, block_count)?;
    Ok(Archive {
        version,
        header_size,
        archive_size,
        sector,
        hash_offset,
        hash_count,
        block_offset,
        block_count,
        files,
        compressed,
        encrypted,
        blocks,
        more,
    })
}

pub(crate) fn flag_names(flags: u32) -> (Vec<&'static str>, u32) {
    const BITS: &[(u32, &str)] = &[
        (EXISTS, "exists"),
        (IMPLODE, "implode"),
        (COMPRESS, "compress"),
        (ENCRYPTED, "encrypted"),
        (0x0002_0000, "fix_key"),
        (0x0100_0000, "single"),
        (0x0200_0000, "deleted"),
        (0x0400_0000, "sector_crc"),
    ];
    let mut names = Vec::new();
    let mut rest = flags;
    for &(bit, name) in BITS {
        if flags & bit != 0 {
            names.push(name);
            rest &= !bit;
        }
    }
    (names, rest)
}

fn header_base(bytes: &[u8]) -> Result<usize, String> {
    if bytes.starts_with(b"MPQ\x1a") {
        return Ok(0);
    }
    if !bytes.starts_with(b"MPQ\x1b") {
        return Err("not an mpq file".into());
    }
    if bytes.len() < 16 {
        return Err("file ends before the mpq user data".into());
    }
    let offset = u32_at(bytes, 8)?;
    usize::try_from(offset).map_err(|_| "mpq header is past the end".to_string())
}

fn high_pos(
    bytes: &[u8],
    base: usize,
    version: u16,
    header_size: u32,
) -> Result<(u16, u16), String> {
    if version < 1 || header_size < 0x2C {
        return Ok((0, 0));
    }
    Ok((u16_at(bytes, base + 0x28)?, u16_at(bytes, base + 0x2A)?))
}

fn table_fits(pos: u64, count: u32, len: u64) -> Result<(), String> {
    if count == 0 {
        return Ok(());
    }
    let bytes = u64::from(count)
        .checked_mul(16)
        .ok_or("table is too large")?;
    let end = pos.checked_add(bytes).ok_or("table is too large")?;
    if end > len {
        return Err("table is past the end".into());
    }
    Ok(())
}

fn read_blocks(
    bytes: &[u8],
    base: u64,
    pos: u64,
    count: u32,
) -> Result<(u64, u64, u64, Vec<Block>, u64), String> {
    if count == 0 {
        return Ok((0, 0, 0, Vec::new(), 0));
    }
    let words = u64::from(count)
        .checked_mul(4)
        .ok_or("table is too large")?;
    let mut words = read_words(bytes, pos, words)?;
    let crypt = crypt_table();
    let key = hash_string(&crypt, "(block table)", 3);
    decrypt(&crypt, &mut words, key);
    let mut files = 0u64;
    let mut compressed = 0u64;
    let mut encrypted = 0u64;
    let mut blocks = Vec::new();
    for entry in words.chunks_exact(4) {
        let flags = entry[3];
        if flags & EXISTS != 0 {
            files += 1;
            if flags & (IMPLODE | COMPRESS) != 0 {
                compressed += 1;
            }
            if flags & ENCRYPTED != 0 {
                encrypted += 1;
            }
        }
        if blocks.len() < BLOCK_CAP {
            let offset = base
                .checked_add(u64::from(entry[0]))
                .ok_or("table is too large")?;
            blocks.push(Block {
                offset,
                stored: u64::from(entry[1]),
                size: u64::from(entry[2]),
                flags,
            });
        }
    }
    let more = u64::from(count) - blocks.len() as u64;
    Ok((files, compressed, encrypted, blocks, more))
}

fn read_words(bytes: &[u8], pos: u64, words: u64) -> Result<Vec<u32>, String> {
    let start = usize::try_from(pos).map_err(|_| "table is too large".to_string())?;
    let count = usize::try_from(words).map_err(|_| "table is too large".to_string())?;
    let byte_len = count.checked_mul(4).ok_or("table is too large")?;
    let end = start.checked_add(byte_len).ok_or("table is too large")?;
    let raw = bytes.get(start..end).ok_or("table is past the end")?;
    let mut out = Vec::with_capacity(count);
    for chunk in raw.chunks_exact(4) {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(chunk);
        out.push(u32::from_le_bytes(buf));
    }
    Ok(out)
}

fn crypt_table() -> [u32; 0x500] {
    let mut crypt = [0u32; 0x500];
    let mut seed = 0x0010_0001u32;
    for index in 0..0x100 {
        let mut at = index;
        while at < 0x500 {
            seed = seed.wrapping_mul(125).wrapping_add(3) % 0x2AAAAB;
            let high = (seed & 0xFFFF) << 16;
            seed = seed.wrapping_mul(125).wrapping_add(3) % 0x2AAAAB;
            crypt[at] = high | (seed & 0xFFFF);
            at += 0x100;
        }
    }
    crypt
}

fn hash_string(crypt: &[u32; 0x500], name: &str, kind: u32) -> u32 {
    let mut seed1 = 0x7FED_7FEDu32;
    let mut seed2 = 0xEEEE_EEEEu32;
    for byte in name.bytes() {
        let ch = u32::from(byte.to_ascii_uppercase());
        seed1 = crypt[((kind << 8) + ch) as usize] ^ seed1.wrapping_add(seed2);
        seed2 = ch
            .wrapping_add(seed1)
            .wrapping_add(seed2)
            .wrapping_add(seed2 << 5)
            .wrapping_add(3);
    }
    seed1
}

fn decrypt(crypt: &[u32; 0x500], words: &mut [u32], mut key: u32) {
    let mut seed = 0xEEEE_EEEEu32;
    for word in words {
        seed = seed.wrapping_add(crypt[0x400 + (key & 0xFF) as usize]);
        let plain = *word ^ key.wrapping_add(seed);
        key = (!key).wrapping_shl(0x15).wrapping_add(0x1111_1111) | (key >> 0x0B);
        seed = plain
            .wrapping_add(seed)
            .wrapping_add(seed << 5)
            .wrapping_add(3);
        *word = plain;
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    let raw = bytes
        .get(at..at + 2)
        .ok_or("file ends before the mpq header")?;
    let mut buf = [0u8; 2];
    buf.copy_from_slice(raw);
    Ok(u16::from_le_bytes(buf))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    let raw = bytes
        .get(at..at + 4)
        .ok_or("file ends before the mpq header")?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(raw);
    Ok(u32::from_le_bytes(buf))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, String> {
    let raw = bytes
        .get(at..at + 8)
        .ok_or("file ends before the mpq header")?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(raw);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: &str = "4d50511a20000000400000000000030020000000300000000100000001000000ddde2d97cb15fc5ab8e1e5b5637bb116ab67483da1d308cad3ba35f8c97133e8";

    fn decode_hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn host() -> crate::claim::Host {
        crate::claim::Host {
            arch: "aarch64",
            os: "macos",
            version: None,
            pac: false,
        }
    }

    fn encrypt(crypt: &[u32; 0x500], words: &[u32], mut key: u32) -> Vec<u32> {
        let mut seed = 0xEEEE_EEEEu32;
        let mut out = Vec::with_capacity(words.len());
        for &plain in words {
            seed = seed.wrapping_add(crypt[0x400 + (key & 0xFF) as usize]);
            let cipher = plain ^ key.wrapping_add(seed);
            key = (!key).wrapping_shl(0x15).wrapping_add(0x1111_1111) | (key >> 0x0B);
            seed = plain
                .wrapping_add(seed)
                .wrapping_add(seed << 5)
                .wrapping_add(3);
            out.push(cipher);
        }
        out
    }

    fn archive_with(blocks: &[[u32; 4]]) -> Vec<u8> {
        let crypt = crypt_table();
        let key = hash_string(&crypt, "(block table)", 3);
        let flat: Vec<u32> = blocks.iter().flatten().copied().collect();
        let coded = encrypt(&crypt, &flat, key);
        let mut out = vec![0u8; 32];
        out[0..4].copy_from_slice(b"MPQ\x1a");
        out[4..8].copy_from_slice(&32u32.to_le_bytes());
        let size = 32u32 + coded.len() as u32 * 4;
        out[8..12].copy_from_slice(&size.to_le_bytes());
        out[14..16].copy_from_slice(&3u16.to_le_bytes());
        out[20..24].copy_from_slice(&32u32.to_le_bytes());
        out[28..32].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        for word in coded {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[test]
    fn table_keys_match_the_storm_constants() {
        let crypt = crypt_table();
        assert_eq!(hash_string(&crypt, "(hash table)", 3), 0xC3AF_3770);
        assert_eq!(hash_string(&crypt, "(block table)", 3), 0xEC83_B3A3);
    }

    #[test]
    fn a_synthetic_archive_has_one_file_and_no_start_claim() {
        let bytes = decode_hex(TINY);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.version, 0);
        assert_eq!(archive.sector, 4096);
        assert_eq!(archive.files, 1);
        assert_eq!(archive.compressed, 0);
        assert_eq!(archive.encrypted, 0);
        assert_eq!(archive.hash_offset, 32);
        assert_eq!(archive.blocks.len(), 1);
        assert_eq!(archive.blocks[0].offset, 32);
        assert_eq!(archive.blocks[0].flags & EXISTS, EXISTS);

        let file = crate::open(&bytes, false).unwrap();
        let page = crate::render("tiny.mpq", &file, false, false);
        assert!(page.contains("format: mpq"), "{page}");
        assert!(page.contains("files: 1"), "{page}");
        assert!(page.contains("sector: 4096"), "{page}");
        assert!(page.contains("no start claim"), "{page}");
        assert!(!page.contains("kind:"), "{page}");
        let json = crate::render("tiny.mpq", &file, true, false);
        assert!(json.contains(r#""format":"mpq""#), "{json}");
        assert!(json.contains(r#""files":1"#), "{json}");
        assert!(json.contains(r#""flags":["exists"]"#), "{json}");
        let err = crate::facts("tiny.mpq", &file, &host()).unwrap_err();
        assert_eq!(err, "no start claim");
    }

    #[test]
    fn user_data_points_at_the_header() {
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(b"MPQ\x1b");
        bytes[8..12].copy_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&decode_hex(TINY));
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.files, 1);
        assert_eq!(archive.hash_offset, 48);
        assert_eq!(archive.block_offset, 64);
        assert_eq!(archive.blocks[0].offset, 48);
    }

    #[test]
    fn flag_counts_and_a_long_table_keep_a_cap() {
        let flags = EXISTS | COMPRESS | ENCRYPTED;
        let one = parse(&archive_with(&[[32, 10, 20, flags]])).unwrap();
        assert_eq!(one.files, 1);
        assert_eq!(one.compressed, 1);
        assert_eq!(one.encrypted, 1);
        assert_eq!(one.blocks[0].stored, 10);
        assert_eq!(one.blocks[0].size, 20);

        let empty = parse(&archive_with(&[[0, 0, 0, 0]])).unwrap();
        assert_eq!(empty.files, 0);
        let page = page::render("empty.mpq", &empty, false);
        assert!(page.contains("flags: none"), "{page}");

        let mut bare = vec![0u8; 32];
        bare[0..4].copy_from_slice(b"MPQ\x1a");
        bare[4..8].copy_from_slice(&32u32.to_le_bytes());
        bare[8..12].copy_from_slice(&32u32.to_le_bytes());
        bare[14..16].copy_from_slice(&3u16.to_le_bytes());
        let none = parse(&bare).unwrap();
        assert_eq!(none.block_count, 0);
        let page = page::render("none.mpq", &none, false);
        assert!(page.contains("rows: []"), "{page}");

        let many = vec![[0u32, 0, 0, EXISTS]; 257];
        let long = parse(&archive_with(&many)).unwrap();
        assert_eq!(long.files, 257);
        assert_eq!(long.blocks.len(), 256);
        assert_eq!(long.more, 1);
        let page = page::render("long.mpq", &long, false);
        assert!(page.contains("more: 1"), "{page}");
    }

    #[test]
    fn a_hostile_mpq_does_not_panic() {
        assert!(!is_mpq(b""));
        assert!(!is_mpq(b"xxMPQ\x1a"));
        assert!(parse(b"").is_err());
        assert!(parse(b"MPQ\x1a").is_err());
        assert!(parse(b"MPQ\x1b").is_err());
        match crate::open(b"nope", false) {
            Err(err) => assert_eq!(err, "not an ELF, Mach-O, or PE file"),
            Ok(_) => panic!("plain bytes are not a start file"),
        }

        let mut short = vec![0u8; 32];
        short[0..4].copy_from_slice(b"MPQ\x1a");
        assert_eq!(parse(&short).unwrap_err(), "mpq header is short");

        let mut shift = vec![0u8; 32];
        shift[0..4].copy_from_slice(b"MPQ\x1a");
        shift[4..8].copy_from_slice(&32u32.to_le_bytes());
        shift[14..16].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert_eq!(parse(&shift).unwrap_err(), "sector shift is too large");

        let mut huge = vec![0u8; 32];
        huge[0..4].copy_from_slice(b"MPQ\x1a");
        huge[4..8].copy_from_slice(&32u32.to_le_bytes());
        huge[14..16].copy_from_slice(&3u16.to_le_bytes());
        huge[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        huge[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse(&huge).unwrap_err(), "table is past the end");
    }
}
