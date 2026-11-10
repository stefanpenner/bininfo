/*
---
why: This file reads one Apple icon set.
uses: bininfo
how: bininfo calls this file when the first four bytes are icns.
This file lists each icon type, size, and encoding.
This file records the body offset.
This file does not decode a pixel.
---
*/

//! One Apple icon set. The file starts with `icns`.
//! This module lists icons. It does not decode a pixel.

pub mod page;

const ICON_CAP: usize = 64;
const OUTSIDE: &str = "icns element is outside this file";

/// One icon. `kind` is the four-byte type.
/// `offset` is the first payload byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icon {
    pub kind: String,
    pub size: u64,
    pub offset: u64,
    pub encoding: &'static str,
    pub pixels: Option<u64>,
}

/// One icon set. `bytes` is the length in the file header.
/// `more` is true when the icon cap stops the walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub bytes: u64,
    pub icons: Vec<Icon>,
    pub more: bool,
}

/// True when the first four bytes are `icns`.
pub fn is_icns(bytes: &[u8]) -> bool {
    bytes.starts_with(b"icns")
}

/// Read each icon header.
/// This function does not decode a pixel.
pub fn parse(bytes: &[u8]) -> Result<Image, String> {
    if !is_icns(bytes) {
        return Err("not an icns file".into());
    }
    let total = u32_at(bytes, 4).ok_or("icns header is short")?;
    if total < 8 {
        return Err("icns header is short".into());
    }
    let end = usize::try_from(total).map_err(|_| OUTSIDE)?;
    if end > bytes.len() {
        return Err("icns file is short".into());
    }
    let mut icons = Vec::new();
    let mut at = 8usize;
    let mut more = false;
    while at + 8 <= end {
        if icons.len() == ICON_CAP {
            more = true;
            break;
        }
        let kind = kind_name(&bytes[at..at + 4]);
        let len = u32_at(bytes, at + 4).ok_or(OUTSIDE)?;
        if len < 8 {
            return Err("icns element is short".into());
        }
        let len = usize::try_from(len).map_err(|_| OUTSIDE)?;
        let next = at.checked_add(len).ok_or(OUTSIDE)?;
        if next > end {
            return Err(OUTSIDE.into());
        }
        let payload_at = at + 8;
        let payload = &bytes[payload_at..next];
        icons.push(Icon {
            encoding: encoding(&kind, payload),
            pixels: pixels(&kind),
            kind,
            size: payload.len() as u64,
            offset: payload_at as u64,
        });
        at = next;
    }
    Ok(Image {
        bytes: u64::from(total),
        icons,
        more,
    })
}

fn kind_name(raw: &[u8]) -> String {
    if raw.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        let text = String::from_utf8_lossy(raw).trim_end().to_string();
        if !text.is_empty() {
            return text;
        }
    }
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encoding(kind: &str, payload: &[u8]) -> &'static str {
    if payload.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return "png";
    }
    if payload.starts_with(&[0xFF, 0xD8]) {
        return "jpeg";
    }
    if payload.starts_with(&[0x00, 0x00, 0x00, 0x0C, b'j', b'P', b' ', b' '])
        || payload.starts_with(&[0xFF, 0x4F, 0xFF, 0x51])
    {
        return "jpeg2000";
    }
    match kind {
        "TOC" => "toc",
        "icnV" => "version",
        "s8mk" | "l8mk" | "h8mk" | "t8mk" => "mask",
        "is32" | "il32" | "ih32" | "it32" => "rgb",
        _ => "other",
    }
}

fn pixels(kind: &str) -> Option<u64> {
    match kind {
        "ic04" => Some(16),
        "ic05" => Some(32),
        "ic07" => Some(128),
        "ic08" => Some(256),
        "ic09" => Some(512),
        "ic10" => Some(1024),
        "ic11" => Some(32),
        "ic12" => Some(64),
        "ic13" => Some(256),
        "ic14" => Some(512),
        _ => None,
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
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

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut chunk = b"IHDR".to_vec();
        chunk.extend_from_slice(&width.to_be_bytes());
        chunk.extend_from_slice(&height.to_be_bytes());
        chunk.extend_from_slice(&[8, 0, 0, 0, 0]);
        let sum = crc32(&chunk);
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(&chunk);
        out.extend_from_slice(&sum.to_be_bytes());
        out
    }

    fn jpeg() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 8, 0, 2, 0, 3, 3];
        out.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0, 0xff, 0xd9]);
        out
    }

    fn icon(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_vec();
        let len = u32::try_from(8 + body.len()).unwrap();
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn file(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for part in parts {
            body.extend_from_slice(part);
        }
        let total = u32::try_from(8 + body.len()).unwrap();
        let mut out = b"icns".to_vec();
        out.extend_from_slice(&total.to_be_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn an_icon_set_lists_each_icon_until_enter() {
        let photo = png(3, 2);
        let bytes = file(&[icon(b"ic08", &photo), icon(b"icp4", &jpeg())]);
        assert!(is_icns(&bytes));
        let image = parse(&bytes).unwrap();
        assert_eq!(image.icons.len(), 2);
        assert_eq!(image.icons[0].kind, "ic08");
        assert_eq!(image.icons[0].encoding, "png");
        assert_eq!(image.icons[0].pixels, Some(256));
        assert_eq!(image.icons[1].kind, "icp4");
        assert_eq!(image.icons[1].encoding, "jpeg");
        assert_eq!(image.icons[1].pixels, None);
        let opened = crate::open(&bytes, false).unwrap();
        let page = crate::render("App.icns", &opened, false, false);
        assert!(page.contains("format: icns"), "{page}");
        assert!(page.contains("ic08"), "{page}");
        assert!(page.contains("encoding: png"), "{page}");
        assert!(page.contains("pixels: 256"), "{page}");
        assert!(page.contains("encoding: jpeg"), "{page}");
        assert!(!page.contains("format: png"), "{page}");
        assert!(!page.contains("format: jpeg"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        let one = crate::step(&bytes, &["ic08"], false, false).unwrap();
        assert!(one.contains("format: png"), "{one}");
        assert!(one.contains("width: 3"), "{one}");
        assert!(one.contains("height: 2"), "{one}");
        assert!(!one.contains("format: icns"), "{one}");
        let other = crate::step(&bytes, &["icp4"], false, false).unwrap();
        assert!(other.contains("format: jpeg"), "{other}");
        assert!(other.contains("width: 3"), "{other}");
        assert!(crate::step(&bytes, &["missing"], false, false).is_none());
        let json = page::render_json("App.icns", &image);
        assert!(json.contains(r#""format":"icns""#), "{json}");
        assert!(json.contains(r#""kind":"ic08""#), "{json}");
        assert!(json.contains(r#""encoding":"png""#), "{json}");
        let err = crate::facts("App.icns", &opened, &host()).unwrap_err();
        assert_eq!(err, "no start claim");
    }

    #[test]
    fn a_short_icon_set_does_not_panic() {
        assert!(!is_icns(b""));
        assert!(!is_icns(b"png"));
        assert!(parse(b"hello").is_err());
        assert!(parse(b"icns").is_err());
        let mut cut = b"icns".to_vec();
        cut.extend_from_slice(&100u32.to_be_bytes());
        assert!(parse(&cut).is_err());
        let mut short = b"icns".to_vec();
        short.extend_from_slice(&16u32.to_be_bytes());
        short.extend_from_slice(b"ic08");
        short.extend_from_slice(&100u32.to_be_bytes());
        assert!(parse(&short).is_err());
        assert!(crate::step(&short, &["ic08"], false, false).is_none());
        let mut tiny = b"icns".to_vec();
        tiny.extend_from_slice(&16u32.to_be_bytes());
        tiny.extend_from_slice(b"ic08");
        tiny.extend_from_slice(&4u32.to_be_bytes());
        assert!(parse(&tiny).is_err());
    }

    #[test]
    fn the_icon_cap_stops_the_list() {
        let mut parts = Vec::new();
        for _ in 0..ICON_CAP + 1 {
            parts.push(icon(b"ic04", b"x"));
        }
        let bytes = file(&parts);
        let image = parse(&bytes).unwrap();
        assert_eq!(image.icons.len(), ICON_CAP);
        assert!(image.more);
        let page = page::render("full.icns", &image, false);
        assert!(page.contains("more: true"), "{page}");
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
