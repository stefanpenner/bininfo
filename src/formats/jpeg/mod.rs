/*
---
why: This file reads one JPEG frame header.
uses: bininfo
how: bininfo calls this file for a JPEG file.
This file reads the first frame and the short APP facts.
This file does not read the scan.
This file does not decode a pixel.
---
*/

//! One JPEG image. The first frame header supplies the size fields.
//! This module does not decode a pixel.

pub mod page;

const MARKER_CAP: usize = 256;
const COMPONENT_CAP: usize = 8;

/// One JPEG image. The first frame header supplies the size fields.
/// `jfif` is the APP0 version text.
/// `density` is the APP0 unit text.
/// `exif` is true for an Exif APP1 prefix.
/// `adobe` is the APP14 transform byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub width: Option<u64>,
    pub height: Option<u64>,
    pub bits: Option<u64>,
    pub components: Option<u64>,
    pub frame: Option<&'static str>,
    pub component_ids: Vec<u8>,
    pub sampling: Vec<u8>,
    pub jfif: Option<String>,
    pub density: Option<String>,
    pub exif: bool,
    pub adobe: Option<u8>,
}

enum Marker<'a> {
    Stuff,
    Stand(u8),
    Seg(u8, &'a [u8]),
}

struct Frame {
    bits: u64,
    height: u64,
    width: u64,
    components: u64,
    word: &'static str,
    ids: Vec<u8>,
    sampling: Vec<u8>,
}

/// True only for a leading SOI marker.
pub fn is_jpeg(bytes: &[u8]) -> bool {
    matches!(bytes.get(..2), Some([0xFF, 0xD8]))
}

/// Read the frame header and the short APP facts.
/// This function does not decode a pixel.
pub fn parse(bytes: &[u8]) -> Result<Image, String> {
    if !is_jpeg(bytes) {
        return Err("not a jpeg file".into());
    }
    let mut image = empty();
    let mut pos = 2usize;
    let mut seen = 0usize;
    while pos < bytes.len() {
        if seen >= MARKER_CAP {
            return Err("jpeg marker cap".into());
        }
        match next_marker(bytes, &mut pos)? {
            Marker::Stuff => {}
            Marker::Stand(code) => {
                seen += 1;
                if code == 0xD9 {
                    return Ok(image);
                }
            }
            Marker::Seg(code, payload) => {
                seen += 1;
                // The scan follows SOS. This walk does not read those bytes.
                if code == 0xDA {
                    return Ok(image);
                }
                apply(&mut image, code, payload)?;
            }
        }
    }
    Err("truncated jpeg".into())
}

fn empty() -> Image {
    Image {
        width: None,
        height: None,
        bits: None,
        components: None,
        frame: None,
        component_ids: Vec::new(),
        sampling: Vec::new(),
        jfif: None,
        density: None,
        exif: false,
        adobe: None,
    }
}

fn next_marker<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<Marker<'a>, String> {
    if bytes.get(*pos) != Some(&0xFF) {
        return Err("jpeg marker is missing".into());
    }
    while bytes.get(*pos) == Some(&0xFF) {
        *pos += 1;
    }
    let code = *bytes.get(*pos).ok_or("truncated jpeg")?;
    *pos += 1;
    // FF 00 is a stuffed FF, not a marker.
    if code == 0x00 {
        return Ok(Marker::Stuff);
    }
    if code == 0x01 || (0xD0..=0xD9).contains(&code) {
        return Ok(Marker::Stand(code));
    }
    let len_at = *pos;
    let len_end = len_at.checked_add(2).ok_or("truncated jpeg")?;
    let raw = bytes.get(len_at..len_end).ok_or("truncated jpeg")?;
    let length = usize::from(u16::from_be_bytes([raw[0], raw[1]]));
    if length < 2 {
        return Err("jpeg marker length is short".into());
    }
    let payload_at = len_end;
    let end = payload_at
        .checked_add(length - 2)
        .ok_or("jpeg marker length is past this file")?;
    let payload = bytes
        .get(payload_at..end)
        .ok_or("jpeg marker length is past this file")?;
    *pos = end;
    Ok(Marker::Seg(code, payload))
}

fn apply(image: &mut Image, code: u8, payload: &[u8]) -> Result<(), String> {
    if let Some(word) = frame_word(code) {
        let frame = read_sof(word, payload)?;
        if image.frame.is_none() {
            image.bits = Some(frame.bits);
            image.height = Some(frame.height);
            image.width = Some(frame.width);
            image.components = Some(frame.components);
            image.frame = Some(frame.word);
            image.component_ids = frame.ids;
            image.sampling = frame.sampling;
        }
        return Ok(());
    }
    match code {
        0xE0 => read_jfif(image, payload),
        0xE1 => {
            read_exif(image, payload);
            Ok(())
        }
        0xEE => {
            read_adobe(image, payload);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn frame_word(code: u8) -> Option<&'static str> {
    match code {
        0xC0 => Some("baseline"),
        0xC1 | 0xC9 => Some("extended"),
        0xC2 | 0xCA => Some("progressive"),
        0xC3 | 0xCB => Some("lossless"),
        _ => None,
    }
}

fn read_sof(word: &'static str, payload: &[u8]) -> Result<Frame, String> {
    if payload.len() < 6 {
        return Err("short jpeg frame".into());
    }
    let components = payload[5];
    if usize::from(components) > COMPONENT_CAP {
        return Err("jpeg frame has too many components".into());
    }
    let need = 6 + usize::from(components) * 3;
    if payload.len() < need {
        return Err("short jpeg frame".into());
    }
    let mut ids = Vec::with_capacity(usize::from(components));
    let mut sampling = Vec::with_capacity(usize::from(components));
    for chunk in payload[6..need].chunks_exact(3) {
        ids.push(chunk[0]);
        sampling.push(chunk[1]);
    }
    Ok(Frame {
        bits: u64::from(payload[0]),
        height: u64::from(u16::from_be_bytes([payload[1], payload[2]])),
        width: u64::from(u16::from_be_bytes([payload[3], payload[4]])),
        components: u64::from(components),
        word,
        ids,
        sampling,
    })
}

fn read_jfif(image: &mut Image, payload: &[u8]) -> Result<(), String> {
    if image.jfif.is_some() || !payload.starts_with(b"JFIF\0") {
        return Ok(());
    }
    if payload.len() < 12 {
        return Err("short jpeg jfif".into());
    }
    let major = payload[5];
    let minor = payload[6];
    let units = payload[7];
    let x = u16::from_be_bytes([payload[8], payload[9]]);
    let y = u16::from_be_bytes([payload[10], payload[11]]);
    image.jfif = Some(format!("{major}.{minor}"));
    image.density = Some(density_text(units, x, y));
    Ok(())
}

fn density_text(units: u8, x: u16, y: u16) -> String {
    let unit = match units {
        0 => "aspect",
        1 => "dpi",
        2 => "dpcm",
        _ => "unknown",
    };
    format!("{x}x{y} {unit}")
}

fn read_exif(image: &mut Image, payload: &[u8]) {
    if payload.starts_with(b"Exif\0\0") {
        image.exif = true;
    }
}

fn read_adobe(image: &mut Image, payload: &[u8]) {
    if image.adobe.is_some() || !payload.starts_with(b"Adobe") {
        return;
    }
    if matches!(payload.len(), 12 | 14) {
        image.adobe = payload.last().copied();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(bytes: &[u8]) -> Image {
        match parse(bytes) {
            Ok(image) => image,
            Err(err) => panic!("{err}"),
        }
    }

    fn marker_segment(code: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xFF, code];
        let length = (payload.len() + 2) as u16;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn sof_segment(
        marker: u8,
        precision: u8,
        height: u16,
        width: u16,
        parts: &[[u8; 3]],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(precision);
        payload.extend_from_slice(&height.to_be_bytes());
        payload.extend_from_slice(&width.to_be_bytes());
        payload.push(parts.len() as u8);
        for part in parts {
            payload.extend_from_slice(part);
        }
        marker_segment(marker, &payload)
    }

    fn with_eoi(body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xD8];
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        bytes
    }

    fn sample_parts() -> [[u8; 3]; 3] {
        [[1, 0x22, 0], [2, 0x11, 1], [3, 0x11, 1]]
    }

    fn baseline() -> Vec<u8> {
        with_eoi(&sof_segment(0xC0, 8, 2, 3, &sample_parts()))
    }

    fn assert_no_claim_keys(page: &str, json: &str) {
        for key in ["size", "sign", "regions", "certs", "load", "kind"] {
            assert!(!page.contains(&format!("\n{key}:")), "{page}");
            assert!(!json.contains(&format!("\"{key}\"")), "{json}");
        }
    }

    #[test]
    fn a_baseline_frame_prints_jpeg() {
        let bytes = baseline();
        assert!(is_jpeg(&bytes));
        let image = parsed(&bytes);
        assert_eq!(image.width, Some(3));
        assert_eq!(image.height, Some(2));
        assert_eq!(image.bits, Some(8));
        assert_eq!(image.components, Some(3));
        assert_eq!(image.frame, Some("baseline"));
        assert_eq!(image.component_ids, vec![1, 2, 3]);
        assert_eq!(image.sampling, vec![0x22, 0x11, 0x11]);
        assert_eq!(image.jfif, None);
        assert!(!image.exif);
        let page = page::render("a.jpg", &image, false);
        assert!(page.contains("format: jpeg"), "{page}");
        assert!(page.contains("A JPEG file has no start claim."), "{page}");
        assert!(page.contains("width: 3"), "{page}");
        assert!(page.contains("height: 2"), "{page}");
        assert!(page.contains("bits: 8"), "{page}");
        assert!(page.contains("components: 3"), "{page}");
        assert!(page.contains("frame: baseline"), "{page}");
        assert!(page.contains("ids: 0x1, 0x2, 0x3"), "{page}");
        let json = page::render_json("a.jpg", &image);
        assert!(json.contains(r#""format":"jpeg""#), "{json}");
        assert!(json.contains(r#""file":"a.jpg""#), "{json}");
        assert!(json.contains(r#""width":3"#), "{json}");
        assert!(json.contains(r#""height":2"#), "{json}");
        assert!(json.contains(r#""bits":8"#), "{json}");
        assert!(json.contains(r#""components":3"#), "{json}");
        assert!(json.contains(r#""frame":"baseline""#), "{json}");
        assert!(json.contains(r#""jfif":null"#), "{json}");
        assert!(json.contains(r#""density":null"#), "{json}");
        assert!(json.contains(r#""exif":false"#), "{json}");
        assert!(json.contains(r#""adobe":null"#), "{json}");
        assert_no_claim_keys(&page, &json);
    }

    #[test]
    fn a_progressive_frame_is_sof2() {
        let bytes = with_eoi(&sof_segment(0xC2, 8, 2, 3, &sample_parts()));
        let image = parsed(&bytes);
        assert_eq!(image.frame, Some("progressive"));
        let page = page::render("a.jpg", &image, false);
        assert!(page.contains("frame: progressive"), "{page}");
    }

    #[test]
    fn arithmetic_frames_use_the_same_words() {
        let one = [[1, 0x11, 0]];
        let word = |marker| parsed(&with_eoi(&sof_segment(marker, 8, 1, 1, &one))).frame;
        assert_eq!(word(0xC0), Some("baseline"));
        assert_eq!(word(0xC1), Some("extended"));
        assert_eq!(word(0xC9), Some("extended"));
        assert_eq!(word(0xC2), Some("progressive"));
        assert_eq!(word(0xCA), Some("progressive"));
        assert_eq!(word(0xC3), Some("lossless"));
        assert_eq!(word(0xCB), Some("lossless"));
    }

    #[test]
    fn a_jfif_app0_shows_version_and_density() {
        let mut payload = b"JFIF\0".to_vec();
        payload.extend_from_slice(&[1, 2, 1, 0x00, 72, 0x00, 72, 0, 0]);
        let bytes = with_eoi(&marker_segment(0xE0, &payload));
        let image = parsed(&bytes);
        assert_eq!(image.jfif.as_deref(), Some("1.2"));
        assert_eq!(image.density.as_deref(), Some("72x72 dpi"));
        assert_eq!(image.width, None);
        let page = page::render("a.jpg", &image, false);
        assert!(page.contains("jfif: 1.2"), "{page}");
        assert!(page.contains("density: 72x72 dpi"), "{page}");
        let json = page::render_json("a.jpg", &image);
        assert!(json.contains(r#""jfif":"1.2""#), "{json}");
        assert!(json.contains(r#""density":"72x72 dpi""#), "{json}");

        let mut aspect = b"JFIF\0".to_vec();
        aspect.extend_from_slice(&[1, 2, 0, 0x00, 1, 0x00, 1]);
        let aspect = parsed(&with_eoi(&marker_segment(0xE0, &aspect)));
        assert_eq!(aspect.density.as_deref(), Some("1x1 aspect"));
        let mut dpcm = b"JFIF\0".to_vec();
        dpcm.extend_from_slice(&[1, 2, 2, 0x00, 10, 0x00, 20]);
        let dpcm = parsed(&with_eoi(&marker_segment(0xE0, &dpcm)));
        assert_eq!(dpcm.density.as_deref(), Some("10x20 dpcm"));
    }

    #[test]
    fn an_exif_app1_sets_the_flag() {
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&[0x4D, 0x4D]);
        let bytes = with_eoi(&marker_segment(0xE1, &payload));
        let image = parsed(&bytes);
        assert!(image.exif);
        assert_eq!(image.width, None);
        let page = page::render("a.jpg", &image, false);
        assert!(page.contains("exif: true"), "{page}");
        let json = page::render_json("a.jpg", &image);
        assert!(json.contains(r#""exif":true"#), "{json}");
    }

    #[test]
    fn an_adobe_app14_keeps_the_transform() {
        for len in [12usize, 14] {
            let mut payload = b"Adobe".to_vec();
            payload.extend_from_slice(&[0x00, 0x64, 0x00, 0x00, 0x00, 0x00]);
            while payload.len() + 1 < len {
                payload.push(0);
            }
            payload.push(1);
            assert_eq!(payload.len(), len);
            let image = parsed(&with_eoi(&marker_segment(0xEE, &payload)));
            assert_eq!(image.adobe, Some(1));
            let page = page::render("a.jpg", &image, false);
            assert!(page.contains("adobe: 1"), "{page}");
        }
    }

    #[test]
    fn a_soi_and_eoi_without_a_frame_is_empty() {
        let image = parsed(&[0xFF, 0xD8, 0xFF, 0xD9]);
        assert_eq!(image.width, None);
        assert_eq!(image.height, None);
        assert_eq!(image.bits, None);
        assert_eq!(image.components, None);
        assert_eq!(image.frame, None);
        assert!(image.component_ids.is_empty());
        assert!(!image.exif);
        assert_eq!(image.adobe, None);
        let page = page::render("a.jpg", &image, false);
        assert!(page.contains("width: null"), "{page}");
        assert!(page.contains("frame: null"), "{page}");
    }

    #[test]
    fn a_scan_stops_at_sos() {
        let mut bytes = vec![0xFF, 0xD8];
        bytes.extend(sof_segment(0xC0, 8, 2, 3, &sample_parts()));
        bytes.extend(marker_segment(0xDA, &[0, 1, 0, 0, 0, 0]));
        bytes.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0x56]);
        let image = parsed(&bytes);
        assert_eq!(image.width, Some(3));
        assert_eq!(image.frame, Some("baseline"));
    }

    #[test]
    fn a_dht_before_the_frame_is_skipped() {
        let mut bytes = vec![0xFF, 0xD8];
        bytes.extend(marker_segment(0xC4, &[0x00]));
        bytes.extend(sof_segment(0xC0, 8, 2, 3, &sample_parts()));
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        let image = parsed(&bytes);
        assert_eq!(image.frame, Some("baseline"));
        assert_eq!(image.width, Some(3));
    }

    #[test]
    fn stuffed_ff_00_is_not_a_marker() {
        let image = parsed(&[0xFF, 0xD8, 0xFF, 0x00, 0xFF, 0xFF, 0xD9]);
        assert_eq!(image.frame, None);
    }

    #[test]
    fn a_truncated_soi_returns_an_error() {
        assert!(is_jpeg(&[0xFF, 0xD8]));
        assert_eq!(
            parse(&[0xFF, 0xD8]).err().as_deref(),
            Some("truncated jpeg")
        );
        assert!(!is_jpeg(&[0xFF]));
        assert!(!is_jpeg(&[]));
        assert!(!is_jpeg(&[0xFF, 0xD9]));
        assert_eq!(parse(&[0xFF]).err().as_deref(), Some("not a jpeg file"));
        assert_eq!(parse(&[]).err().as_deref(), Some("not a jpeg file"));
    }

    #[test]
    fn a_bad_marker_length_returns_an_error() {
        let short = [0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x01];
        assert_eq!(
            parse(&short).err().as_deref(),
            Some("jpeg marker length is short")
        );
        let past = [0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08];
        assert_eq!(
            parse(&past).err().as_deref(),
            Some("jpeg marker length is past this file")
        );
    }

    #[test]
    fn a_short_frame_or_wide_frame_returns_an_error() {
        let short = [
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x08, 0x08, 0x00, 0x01, 0x00, 0x01, 0x03, 0xFF, 0xD9,
        ];
        assert_eq!(parse(&short).err().as_deref(), Some("short jpeg frame"));
        let wide = [
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x08, 0x08, 0x00, 0x01, 0x00, 0x01, 0x09, 0xFF, 0xD9,
        ];
        assert_eq!(
            parse(&wide).err().as_deref(),
            Some("jpeg frame has too many components")
        );
    }

    #[test]
    fn a_marker_cap_stops() {
        // The walk accepts 256 markers. The next marker returns an error.
        let mut ok_bytes = vec![0xFF, 0xD8];
        for _ in 0..255 {
            ok_bytes.extend_from_slice(&[0xFF, 0x01]);
        }
        ok_bytes.extend_from_slice(&[0xFF, 0xD9]);
        let image = parsed(&ok_bytes);
        assert_eq!(image.frame, None);

        let mut full = vec![0xFF, 0xD8];
        for _ in 0..256 {
            full.extend_from_slice(&[0xFF, 0x01]);
        }
        full.extend_from_slice(&[0xFF, 0xD9]);
        assert_eq!(parse(&full).err().as_deref(), Some("jpeg marker cap"));
    }
}
