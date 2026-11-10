/*
---
why: This file reads one PNG header.
uses: bininfo
how: bininfo calls this file when the bytes start with the PNG signature.
This file reads the IHDR chunk.
This file does not check the chunk CRC.
This file does not decode a pixel.
---
*/

//! One PNG image. The IHDR chunk supplies the size fields.
//! This module does not decode a pixel.

pub mod page;

const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// One PNG image. The fields come from the first IHDR chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub width: u64,
    pub height: u64,
    pub depth: u64,
    pub color: &'static str,
}

/// True when the first eight bytes are the PNG signature.
pub fn is_png(bytes: &[u8]) -> bool {
    bytes.starts_with(&SIG)
}

/// Read the IHDR chunk.
/// This function does not decode a pixel.
pub fn parse(bytes: &[u8]) -> Result<Image, String> {
    if !is_png(bytes) {
        return Err("not a png file".into());
    }
    let header = bytes.get(8..29).ok_or("png header is short")?;
    let len = u32_be(header, 0)?;
    if len != 13 || &header[4..8] != b"IHDR" {
        return Err("png IHDR is wrong".into());
    }
    let data = &header[8..21];
    let width = u64::from(u32_be(data, 0)?);
    let height = u64::from(u32_be(data, 4)?);
    if width == 0 || height == 0 {
        return Err("png size is zero".into());
    }
    let depth = u64::from(data[8]);
    if !matches!(depth, 1 | 2 | 4 | 8 | 16) {
        return Err("png depth is wrong".into());
    }
    let color = color_word(data[9]).ok_or("png color is wrong")?;
    Ok(Image {
        width,
        height,
        depth,
        color,
    })
}

fn color_word(kind: u8) -> Option<&'static str> {
    match kind {
        0 => Some("gray"),
        2 => Some("rgb"),
        3 => Some("palette"),
        4 => Some("gray-alpha"),
        6 => Some("rgba"),
        _ => None,
    }
}

fn u32_be(bytes: &[u8], at: usize) -> Result<u32, String> {
    let raw = bytes.get(at..at + 4).ok_or("png header is short")?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    pub(super) fn png(width: u32, height: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[8, 0, 0, 0, 0]);
        let mut chunk = b"IHDR".to_vec();
        chunk.extend_from_slice(&data);
        let sum = crc32(&chunk);
        let mut out = SIG.to_vec();
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(&chunk);
        out.extend_from_slice(&sum.to_be_bytes());
        out
    }

    #[test]
    fn a_png_header_lists_the_frame() {
        let bytes = png(3, 2);
        assert!(is_png(&bytes));
        let image = parse(&bytes).unwrap();
        assert_eq!(image.width, 3);
        assert_eq!(image.height, 2);
        assert_eq!(image.depth, 8);
        assert_eq!(image.color, "gray");
        let file = crate::open(&bytes, false).unwrap();
        let page = crate::render("a.png", &file, false, false);
        assert!(page.contains("format: png"), "{page}");
        assert!(page.contains("width: 3"), "{page}");
        assert!(page.contains("height: 2"), "{page}");
        assert!(page.contains("depth: 8"), "{page}");
        assert!(page.contains("color: gray"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        let json = page::render_json("a.png", &image);
        assert!(json.contains(r#""format":"png""#), "{json}");
        assert!(json.contains(r#""width":3"#), "{json}");
        assert!(json.contains(r#""color":"gray""#), "{json}");
        let err = crate::facts("a.png", &file, &host()).unwrap_err();
        assert_eq!(err, "no start claim");
    }

    #[test]
    fn a_short_or_bad_png_does_not_panic() {
        assert!(!is_png(b""));
        assert!(!is_png(b"icns"));
        assert!(parse(b"hello").is_err());
        assert!(parse(&SIG).is_err());
        let mut bad = png(1, 1);
        bad[11] = 0;
        assert!(parse(&bad).is_err());
        assert!(parse(&png(0, 1)).is_err());
        let mut wide = SIG.to_vec();
        wide.extend_from_slice(&13u32.to_be_bytes());
        wide.extend_from_slice(b"IHDR");
        wide.extend_from_slice(&0u32.to_be_bytes());
        wide.extend_from_slice(&1u32.to_be_bytes());
        wide.extend_from_slice(&[8, 0, 0, 0, 0]);
        assert!(parse(&wide).is_err());
    }

    fn host() -> crate::claim::Host {
        crate::claim::Host {
            arch: "aarch64",
            os: "macos",
            version: None,
            pac: true,
        }
    }
}
