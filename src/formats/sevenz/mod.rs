/*
---
why: This file reads one 7z signature header.
uses: bininfo
how: bininfo calls this file when the first bytes are the 7z signature.
This file stores the next-header CRC.
This file does not check that CRC.
This file does not decode LZMA.
---
*/

//! One 7z archive. The record is the 32-byte signature header.
//! This module does not decode LZMA.

pub mod page;

const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const START: usize = 32;

/// One 7z archive. `header_crc` is the next-header CRC.
/// This module stores that CRC and does not check it.
/// `encoded` stays true.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    pub major: u8,
    pub minor: u8,
    pub header_offset: u64,
    pub header_size: u64,
    pub header_crc: u32,
    pub encoded: bool,
}

/// True only when the first six bytes are the 7z signature.
pub fn is_sevenz(bytes: &[u8]) -> bool {
    bytes.starts_with(&SIGNATURE)
}

/// Read the 32-byte signature header.
/// This function does not read the next header.
pub fn parse(bytes: &[u8]) -> Result<Archive, String> {
    if !is_sevenz(bytes) {
        return Err("not a 7z file".into());
    }
    let raw = bytes
        .get(..START)
        .ok_or("file ends before the 7z start header")?;
    let header_offset = u64_le(raw, 12)?;
    let header_size = u64_le(raw, 20)?;
    // The next-header CRC is stored and not checked.
    // A size outside this file is still stored.
    Ok(Archive {
        major: raw[6],
        minor: raw[7],
        header_offset,
        header_size,
        header_crc: u32_le(raw, 28)?,
        encoded: true,
    })
}

fn u32_le(bytes: &[u8], at: usize) -> Result<u32, String> {
    let s = bytes
        .get(at..at + 4)
        .ok_or("file ends before the 7z start header")?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_le(bytes: &[u8], at: usize) -> Result<u64, String> {
    let s = bytes
        .get(at..at + 8)
        .ok_or("file ends before the 7z start header")?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature() -> [u8; 6] {
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]
    }

    fn start_header(major: u8, minor: u8, offset: u64, size: u64, crc: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&signature());
        bytes.push(major);
        bytes.push(minor);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes
    }

    #[test]
    fn a_version_0_4_header_prints_7z() {
        let bytes = start_header(0, 4, 32, 10, 0);
        assert_eq!(bytes.len(), 32);
        assert!(is_sevenz(&bytes));
        let archive = match parse(&bytes) {
            Ok(archive) => archive,
            Err(err) => {
                assert!(false, "{err}");
                return;
            }
        };
        assert_eq!(archive.major, 0);
        assert_eq!(archive.minor, 4);
        assert_eq!(archive.header_offset, 32);
        assert_eq!(archive.header_size, 10);
        assert_eq!(archive.header_crc, 0);
        assert!(archive.encoded);
        let page = page::render("a.7z", &archive, false);
        assert!(page.contains("format: 7z"), "{page}");
        assert!(page.contains("encoded"), "{page}");
        assert!(page.contains("version: 0.4"), "{page}");
        assert!(!page.contains("\nsize:"), "{page}");
        assert!(!page.contains("\nsign:"), "{page}");
        assert!(!page.contains("\nregions:"), "{page}");
        assert!(!page.contains("\ncerts:"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        assert!(!page.contains("\nkind:"), "{page}");
        let json = page::render_json("a.7z", &archive);
        assert!(json.contains(r#""format":"7z""#), "{json}");
        assert!(json.contains(r#""major":0"#), "{json}");
        assert!(json.contains(r#""minor":4"#), "{json}");
        assert!(json.contains(r#""header_offset":32"#), "{json}");
        assert!(json.contains(r#""header_size":10"#), "{json}");
        assert!(json.contains(r#""header_crc":0"#), "{json}");
        assert!(json.contains(r#""encoded":true"#), "{json}");
        assert!(!json.contains(r#""kind""#), "{json}");
        assert!(!json.contains(r#""load""#), "{json}");
    }

    #[test]
    fn a_signature_alone_returns_err() {
        let bytes = signature();
        assert!(is_sevenz(&bytes));
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn a_wrong_first_byte_is_not_sevenz() {
        let mut bytes = start_header(0, 4, 32, 10, 0);
        bytes[0] = 0;
        assert!(!is_sevenz(&bytes));
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn a_huge_next_header_size_is_not_allocated() {
        let bytes = start_header(0, 4, 0, u64::MAX, 0);
        assert_eq!(bytes.len(), 32);
        let archive = match parse(&bytes) {
            Ok(archive) => archive,
            Err(err) => {
                assert!(false, "{err}");
                return;
            }
        };
        assert_eq!(archive.header_size, u64::MAX);
        assert_eq!(archive.header_offset, 0);
        assert!(archive.encoded);
    }
}
