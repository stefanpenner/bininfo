/*
---
why: This file reads one ISOBMFF box tree.
uses: bininfo
how: bininfo calls this file for an ftyp file.
This file does not decode a sample.
---
*/

//! One ISOBMFF movie. The major brand sets the format word.
//! This module does not decode a sample.

pub mod page;

const BOX_CAP: usize = 4096;
const BRAND_CAP: usize = 32;
const DEPTH_CAP: usize = 8;
const CODEC_CAP: usize = 8;

/// One ISOBMFF movie.
/// The major brand sets the format word.
/// This record does not hold samples.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Movie {
    pub format: String,
    pub brand: String,
    pub minor: u32,
    pub brands: Vec<String>,
    pub timescale: Option<u64>,
    pub duration: Option<u64>,
    pub tracks: u64,
    pub width: Option<u64>,
    pub height: Option<u64>,
    pub video: u64,
    pub audio: u64,
    pub codecs: Vec<String>,
    pub more: bool,
}

struct Limit {
    boxes: usize,
    first: bool,
    have_ftyp: bool,
}

struct Head {
    header: usize,
    end: usize,
    kind: [u8; 4],
}

enum BoxErr {
    Small,
    Outside,
}

/// True when the first box type is ftyp.
/// The check reads the header only.
pub fn is_isobmff(bytes: &[u8]) -> bool {
    if bytes.len() < 12 || bytes.get(4..8) != Some(b"ftyp".as_slice()) {
        return false;
    }
    match be_u32(bytes, 0) {
        Some(1) => bytes.len() >= 16,
        Some(size) => size >= 16,
        None => false,
    }
}

/// Read one ISOBMFF movie.
/// This function does not decode a sample.
pub fn parse(bytes: &[u8]) -> Result<Movie, String> {
    if !is_isobmff(bytes) {
        return Err("not an isobmff file".to_string());
    }
    let mut movie = blank_movie();
    let mut limit = Limit {
        boxes: 0,
        first: true,
        have_ftyp: false,
    };
    walk(bytes, 0, &mut movie, &mut limit)?;
    if movie.format.is_empty() {
        movie.format = "isobmff".to_string();
    }
    Ok(movie)
}

fn blank_movie() -> Movie {
    Movie {
        format: String::new(),
        brand: String::new(),
        minor: 0,
        brands: Vec::new(),
        timescale: None,
        duration: None,
        tracks: 0,
        width: None,
        height: None,
        video: 0,
        audio: 0,
        codecs: Vec::new(),
        more: false,
    }
}

fn walk(bytes: &[u8], depth: usize, movie: &mut Movie, limit: &mut Limit) -> Result<(), String> {
    let mut at = 0usize;
    while at < bytes.len() {
        if limit.boxes >= BOX_CAP {
            movie.more = true;
            return Ok(());
        }
        let head = match read_head(bytes, at) {
            Ok(head) => head,
            Err(err) => return box_stop(movie, limit, err),
        };
        if head.end <= at {
            return box_stop(movie, limit, BoxErr::Small);
        }
        let Some(start) = at.checked_add(head.header) else {
            return box_stop(movie, limit, BoxErr::Outside);
        };
        if start > head.end || head.end > bytes.len() {
            return box_stop(movie, limit, BoxErr::Outside);
        }
        limit.boxes += 1;
        limit.first = false;
        apply(head.kind, &bytes[start..head.end], depth, movie, limit)?;
        at = head.end;
    }
    Ok(())
}

fn apply(
    kind: [u8; 4],
    payload: &[u8],
    depth: usize,
    movie: &mut Movie,
    limit: &mut Limit,
) -> Result<(), String> {
    if kind == *b"trak" {
        movie.tracks = movie.tracks.saturating_add(1);
    }
    match &kind {
        b"ftyp" => read_ftyp(payload, movie, limit),
        b"mvhd" => {
            read_mvhd(payload, movie);
            Ok(())
        }
        b"tkhd" => {
            read_tkhd(payload, movie);
            Ok(())
        }
        b"hdlr" => {
            read_hdlr(payload, movie);
            Ok(())
        }
        b"ispe" => {
            read_ispe(payload, movie);
            Ok(())
        }
        b"stsd" => {
            read_stsd(payload, movie);
            Ok(())
        }
        b"mdat" => Ok(()),
        b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"meta" | b"iprp" | b"ipco" => {
            enter(kind, payload, depth, movie, limit)
        }
        _ => Ok(()),
    }
}

fn enter(
    kind: [u8; 4],
    payload: &[u8],
    depth: usize,
    movie: &mut Movie,
    limit: &mut Limit,
) -> Result<(), String> {
    if depth >= DEPTH_CAP {
        if !payload.is_empty() {
            movie.more = true;
        }
        return Ok(());
    }
    // The meta box is a full box. Child boxes follow the version and the flags.
    if kind == *b"meta" {
        if payload.len() < 4 {
            movie.more = true;
            return Ok(());
        }
        return walk(&payload[4..], depth + 1, movie, limit);
    }
    walk(payload, depth + 1, movie, limit)
}

// Size 0 ends at the parent end. Size 1 has a 16-byte header.
fn read_head(bytes: &[u8], at: usize) -> Result<Head, BoxErr> {
    if bytes.len().saturating_sub(at) < 8 {
        return Err(BoxErr::Outside);
    }
    let size = be_u32(bytes, at).ok_or(BoxErr::Outside)?;
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&bytes[at + 4..at + 8]);
    match size {
        1 => {
            if bytes.len().saturating_sub(at) < 16 {
                return Err(BoxErr::Outside);
            }
            let large = be_u64(bytes, at + 8).ok_or(BoxErr::Outside)?;
            if large < 16 {
                return Err(BoxErr::Small);
            }
            let total = usize::try_from(large).map_err(|_| BoxErr::Outside)?;
            let end = at.checked_add(total).ok_or(BoxErr::Outside)?;
            if end > bytes.len() {
                return Err(BoxErr::Outside);
            }
            Ok(Head {
                header: 16,
                end,
                kind,
            })
        }
        0 => Ok(Head {
            header: 8,
            end: bytes.len(),
            kind,
        }),
        n if n < 8 => Err(BoxErr::Small),
        n => {
            let total = usize::try_from(n).map_err(|_| BoxErr::Outside)?;
            let end = at.checked_add(total).ok_or(BoxErr::Outside)?;
            if end > bytes.len() {
                return Err(BoxErr::Outside);
            }
            Ok(Head {
                header: 8,
                end,
                kind,
            })
        }
    }
}

fn box_stop(movie: &mut Movie, limit: &Limit, err: BoxErr) -> Result<(), String> {
    if limit.first {
        return Err(match err {
            BoxErr::Small => "box size is too small".to_string(),
            BoxErr::Outside => "box is outside this file".to_string(),
        });
    }
    movie.more = true;
    Ok(())
}

fn read_ftyp(payload: &[u8], movie: &mut Movie, limit: &mut Limit) -> Result<(), String> {
    if limit.have_ftyp {
        return Ok(());
    }
    if payload.len() < 8 {
        return Err("ftyp ends before the major brand".to_string());
    }
    let major = &payload[0..4];
    movie.brand = fourcc(major);
    movie.minor =
        be_u32(payload, 4).ok_or_else(|| "ftyp ends before the minor version".to_string())?;
    movie.format = format_word(major);
    let mut at = 8usize;
    while payload.len().saturating_sub(at) >= 4 {
        if movie.brands.len() >= BRAND_CAP {
            movie.more = true;
            break;
        }
        let Some(end) = at.checked_add(4) else {
            movie.more = true;
            break;
        };
        let Some(raw) = payload.get(at..end) else {
            movie.more = true;
            break;
        };
        movie.brands.push(fourcc(raw));
        at = end;
    }
    if at < payload.len() {
        movie.more = true;
    }
    limit.have_ftyp = true;
    Ok(())
}

fn read_mvhd(payload: &[u8], movie: &mut Movie) {
    if movie.timescale.is_some() {
        return;
    }
    let Some(version) = payload.first().copied() else {
        movie.more = true;
        return;
    };
    match version {
        0 => {
            let Some(scale) = be_u32(payload, 12) else {
                movie.more = true;
                return;
            };
            let Some(duration) = be_u32(payload, 16) else {
                movie.more = true;
                return;
            };
            movie.timescale = Some(u64::from(scale));
            movie.duration = Some(u64::from(duration));
        }
        1 => {
            let Some(scale) = be_u32(payload, 20) else {
                movie.more = true;
                return;
            };
            let Some(duration) = be_u64(payload, 24) else {
                movie.more = true;
                return;
            };
            movie.timescale = Some(u64::from(scale));
            movie.duration = Some(duration);
        }
        _ => movie.more = true,
    }
}

fn read_tkhd(payload: &[u8], movie: &mut Movie) {
    if movie.width.is_some() {
        return;
    }
    let Some(version) = payload.first().copied() else {
        movie.more = true;
        return;
    };
    let width_at = match version {
        0 => 76,
        1 => 88,
        _ => {
            movie.more = true;
            return;
        }
    };
    let Some(width) = be_u32(payload, width_at) else {
        movie.more = true;
        return;
    };
    let Some(height) = be_u32(payload, width_at + 4) else {
        movie.more = true;
        return;
    };
    movie.width = Some(u64::from(width / 65536));
    movie.height = Some(u64::from(height / 65536));
}

fn read_hdlr(payload: &[u8], movie: &mut Movie) {
    let Some(kind) = payload.get(8..12) else {
        movie.more = true;
        return;
    };
    if kind == b"vide" {
        movie.video = movie.video.saturating_add(1);
    } else if kind == b"soun" {
        movie.audio = movie.audio.saturating_add(1);
    }
}

fn read_ispe(payload: &[u8], movie: &mut Movie) {
    if movie.width.is_some() {
        return;
    }
    let Some(width) = be_u32(payload, 4) else {
        movie.more = true;
        return;
    };
    let Some(height) = be_u32(payload, 8) else {
        movie.more = true;
        return;
    };
    movie.width = Some(u64::from(width));
    movie.height = Some(u64::from(height));
}

// A sample entry follows the version, the flags, and the entry count.
fn read_stsd(payload: &[u8], movie: &mut Movie) {
    let Some(count) = be_u32(payload, 4) else {
        movie.more = true;
        return;
    };
    if count == 0 {
        return;
    }
    if movie.codecs.len() >= CODEC_CAP {
        movie.more = true;
        return;
    }
    let Some(kind) = first_entry(&payload[8..]) else {
        movie.more = true;
        return;
    };
    movie.codecs.push(fourcc(&kind));
}

fn first_entry(entries: &[u8]) -> Option<[u8; 4]> {
    if entries.len() < 8 {
        return None;
    }
    let size = be_u32(entries, 0)?;
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&entries[4..8]);
    let ok = match size {
        0 => true,
        1 => match be_u64(entries, 8) {
            Some(large) => match usize::try_from(large) {
                Ok(total) => total >= 16 && total <= entries.len(),
                Err(_) => false,
            },
            None => false,
        },
        n if n < 8 => false,
        n => usize::try_from(n).is_ok_and(|total| total <= entries.len()),
    };
    if ok {
        Some(kind)
    } else {
        None
    }
}

fn format_word(raw: &[u8]) -> String {
    let Some(text) = printable_brand(raw) else {
        return "isobmff".to_string();
    };
    let brand = std::str::from_utf8(text).unwrap_or("");
    match brand {
        "heic" | "heix" | "hevc" | "hevx" => "heic",
        "mif1" | "msf1" => "heif",
        "avif" | "avis" => "avif",
        "crx" => "cr3",
        "qt" => "mov",
        "isom" | "mp41" | "mp42" | "iso2" | "avc1" | "iso4" | "iso5" | "iso6" | "dash" | "M4V"
        | "M4A" | "M4VP" => "mp4",
        "" => "isobmff",
        other => other,
    }
    .to_string()
}

fn fourcc(raw: &[u8]) -> String {
    if let Some(text) = printable_brand(raw) {
        if let Ok(brand) = std::str::from_utf8(text) {
            if !brand.is_empty() {
                return brand.to_string();
            }
        }
    }
    let mut out = String::new();
    for byte in raw.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn printable_brand(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() != 4 || raw.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
        return None;
    }
    let end = raw
        .iter()
        .rposition(|byte| *byte != b' ')
        .map(|index| index + 1)
        .unwrap_or(0);
    Some(&raw[..end])
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let slice = bytes.get(at..end)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn be_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let slice = bytes.get(at..end)?;
    Some(u64::from_be_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn box_of(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = u32::try_from(8 + payload.len()).unwrap();
        let mut out = Vec::with_capacity(payload.len() + 8);
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out
    }

    fn ftyp(major: &[u8; 4], minor: u32, brands: &[[u8; 4]]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(8 + brands.len() * 4);
        payload.extend_from_slice(major);
        payload.extend_from_slice(&minor.to_be_bytes());
        for brand in brands {
            payload.extend_from_slice(brand);
        }
        box_of(b"ftyp", &payload)
    }

    fn mvhd(version: u8, timescale: u32, duration: u64) -> Vec<u8> {
        let mut payload = vec![0u8; if version == 1 { 32 } else { 20 }];
        payload[0] = version;
        if version == 1 {
            payload[20..24].copy_from_slice(&timescale.to_be_bytes());
            payload[24..32].copy_from_slice(&duration.to_be_bytes());
        } else {
            payload[12..16].copy_from_slice(&timescale.to_be_bytes());
            payload[16..20].copy_from_slice(&u32::try_from(duration).unwrap().to_be_bytes());
        }
        box_of(b"mvhd", &payload)
    }

    fn tkhd(version: u8, width_fixed: u32, height_fixed: u32) -> Vec<u8> {
        let width_at = if version == 1 { 88 } else { 76 };
        let mut payload = vec![0u8; width_at + 8];
        payload[0] = version;
        payload[width_at..width_at + 4].copy_from_slice(&width_fixed.to_be_bytes());
        payload[width_at + 4..width_at + 8].copy_from_slice(&height_fixed.to_be_bytes());
        box_of(b"tkhd", &payload)
    }

    fn hdlr(kind: &[u8; 4]) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[8..12].copy_from_slice(kind);
        box_of(b"hdlr", &payload)
    }

    fn stsd(codec: &[u8; 4]) -> Vec<u8> {
        let entry = box_of(codec, &[0u8; 8]);
        let mut payload = vec![0u8; 8];
        payload[4..8].copy_from_slice(&1u32.to_be_bytes());
        payload.extend(entry);
        box_of(b"stsd", &payload)
    }

    fn ispe(width: u32, height: u32) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[4..8].copy_from_slice(&width.to_be_bytes());
        payload[8..12].copy_from_slice(&height.to_be_bytes());
        box_of(b"ispe", &payload)
    }

    fn meta_ispe(width: u32, height: u32) -> Vec<u8> {
        let mut body = vec![0u8; 4];
        body.extend(hdlr(b"pict"));
        let ipco = box_of(b"ipco", &ispe(width, height));
        body.extend(box_of(b"iprp", &ipco));
        box_of(b"meta", &body)
    }

    fn with_ftyp(major: &[u8; 4], rest: &[u8]) -> Vec<u8> {
        let mut bytes = ftyp(major, 0, &[]);
        bytes.extend_from_slice(rest);
        bytes
    }

    fn assert_format(major: &[u8; 4], format: &str, brand: &str) {
        let bytes = ftyp(major, 0, &[]);
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.format, format, "{major:?}");
        assert_eq!(movie.brand, brand, "{major:?}");
        let page = page::render("a.bin", &movie, false);
        assert!(page.contains(&format!("format: {format}")), "{page}");
        let json = page::render_json("a.bin", &movie);
        assert!(json.contains(&format!(r#""format":"{format}""#)), "{json}");
    }

    #[test]
    fn an_isom_brand_is_mp4() {
        let bytes = ftyp(b"isom", 0, &[]);
        assert!(is_isobmff(&bytes));
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.format, "mp4");
        assert_eq!(movie.brand, "isom");
        assert_eq!(movie.minor, 0);
        assert!(movie.brands.is_empty());
        assert_eq!(movie.timescale, None);
        assert_eq!(movie.duration, None);
        assert_eq!(movie.tracks, 0);
        assert_eq!(movie.width, None);
        assert_eq!(movie.height, None);
        assert_eq!(movie.video, 0);
        assert_eq!(movie.audio, 0);
        assert!(movie.codecs.is_empty());
        assert!(!movie.more);
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("format: mp4"), "{page}");
        assert!(
            page.contains("This media file has no start claim."),
            "{page}"
        );
        assert!(page.contains("brand: isom"), "{page}");
        assert!(page.contains("timescale: null"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        assert!(!page.contains("\nkind:"), "{page}");
        assert!(!page.contains("\nsize:"), "{page}");
        assert!(!page.contains("\nsign:"), "{page}");
        let json = page::render_json("a.mp4", &movie);
        assert!(json.contains(r#""file":"a.mp4""#), "{json}");
        assert!(json.contains(r#""format":"mp4""#), "{json}");
        assert!(json.contains(r#""brand":"isom""#), "{json}");
        assert!(json.contains(r#""minor":0"#), "{json}");
        assert!(json.contains(r#""brands":[]"#), "{json}");
        assert!(json.contains(r#""timescale":null"#), "{json}");
        assert!(json.contains(r#""duration":null"#), "{json}");
        assert!(json.contains(r#""tracks":0"#), "{json}");
        assert!(json.contains(r#""width":null"#), "{json}");
        assert!(json.contains(r#""height":null"#), "{json}");
        assert!(json.contains(r#""video":0"#), "{json}");
        assert!(json.contains(r#""audio":0"#), "{json}");
        assert!(json.contains(r#""codecs":[]"#), "{json}");
        assert!(json.contains(r#""more":false"#), "{json}");
        assert!(!json.contains(r#""load""#), "{json}");
        assert!(!json.contains(r#""kind""#), "{json}");
        assert!(!json.contains(r#""size""#), "{json}");
        assert!(!json.contains(r#""sign""#), "{json}");
        assert!(!json.contains(r#""regions""#), "{json}");
        assert!(!json.contains(r#""certs""#), "{json}");
    }

    #[test]
    fn a_heic_brand_is_heic() {
        let bytes = ftyp(b"heic", 0x0100, &[]);
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.format, "heic");
        assert_eq!(movie.brand, "heic");
        assert_eq!(movie.minor, 0x0100);
        let page = page::render("a.heic", &movie, false);
        assert!(page.contains("format: heic"), "{page}");
        let json = page::render_json("a.heic", &movie);
        assert!(json.contains(r#""format":"heic""#), "{json}");
        assert!(json.contains(r#""minor":256"#), "{json}");
    }

    #[test]
    fn a_crx_brand_is_cr3() {
        assert_format(b"crx ", "cr3", "crx");
    }

    #[test]
    fn a_qt_brand_is_mov() {
        assert_format(b"qt  ", "mov", "qt");
    }

    #[test]
    fn heif_and_avif_brands() {
        assert_format(b"mif1", "heif", "mif1");
        assert_format(b"avif", "avif", "avif");
    }

    #[test]
    fn other_brands_use_the_same_map() {
        let rows: &[([u8; 4], &str, &str)] = &[
            (*b"heix", "heic", "heix"),
            (*b"hevc", "heic", "hevc"),
            (*b"hevx", "heic", "hevx"),
            (*b"msf1", "heif", "msf1"),
            (*b"avis", "avif", "avis"),
            (*b"mp41", "mp4", "mp41"),
            (*b"mp42", "mp4", "mp42"),
            (*b"iso2", "mp4", "iso2"),
            (*b"avc1", "mp4", "avc1"),
            (*b"iso4", "mp4", "iso4"),
            (*b"iso5", "mp4", "iso5"),
            (*b"iso6", "mp4", "iso6"),
            (*b"dash", "mp4", "dash"),
            (*b"M4V ", "mp4", "M4V"),
            (*b"M4A ", "mp4", "M4A"),
            (*b"M4VP", "mp4", "M4VP"),
            (*b"wave", "wave", "wave"),
            (*b"\0\0\0\0", "isobmff", "00000000"),
            (*b"    ", "isobmff", "20202020"),
        ];
        for &(major, format, brand) in rows {
            assert_format(&major, format, brand);
        }
    }

    #[test]
    fn an_mvhd_prints_timescale_and_duration() {
        let moov = box_of(b"moov", &mvhd(0, 1000, 50));
        let bytes = with_ftyp(b"isom", &moov);
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.timescale, Some(1000));
        assert_eq!(movie.duration, Some(50));
        assert!(!movie.more);
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("timescale: 1000"), "{page}");
        assert!(page.contains("duration: 50"), "{page}");
        let json = page::render_json("a.mp4", &movie);
        assert!(json.contains(r#""timescale":1000"#), "{json}");
        assert!(json.contains(r#""duration":50"#), "{json}");
    }

    #[test]
    fn a_wide_mvhd_stores_a_long_duration() {
        let moov = box_of(b"moov", &mvhd(1, 600, 0x1_0000_0000));
        let movie = parse(&with_ftyp(b"isom", &moov)).unwrap();
        assert_eq!(movie.timescale, Some(600));
        assert_eq!(movie.duration, Some(0x1_0000_0000));
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("timescale: 600"), "{page}");
        assert!(page.contains("duration: 4294967296"), "{page}");
        let json = page::render_json("a.mp4", &movie);
        assert!(json.contains(r#""duration":4294967296"#), "{json}");
    }

    #[test]
    fn one_trak_is_counted() {
        let moov = box_of(b"moov", &box_of(b"trak", &[]));
        let movie = parse(&with_ftyp(b"isom", &moov)).unwrap();
        assert_eq!(movie.tracks, 1);
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("tracks: 1 "), "{page}");
        let json = page::render_json("a.mp4", &movie);
        assert!(json.contains(r#""tracks":1"#), "{json}");
    }

    #[test]
    fn a_track_header_stores_whole_pixels() {
        let header = tkhd(0, (1920 << 16) + 9, 1080 << 16);
        let trak = box_of(b"trak", &header);
        let moov = box_of(b"moov", &trak);
        let mut bytes = with_ftyp(b"isom", &moov);
        bytes.extend(meta_ispe(10, 12));
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.width, Some(1920));
        assert_eq!(movie.height, Some(1080));
        assert_eq!(movie.video, 0);
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("width: 1920"), "{page}");
        assert!(page.contains("height: 1080"), "{page}");
        let json = page::render_json("a.mp4", &movie);
        assert!(json.contains(r#""width":1920"#), "{json}");
        assert!(json.contains(r#""height":1080"#), "{json}");

        let wide = tkhd(1, 640 << 16, 480 << 16);
        let moov = box_of(b"moov", &box_of(b"trak", &wide));
        let movie = parse(&with_ftyp(b"qt  ", &moov)).unwrap();
        assert_eq!(movie.format, "mov");
        assert_eq!(movie.width, Some(640));
        assert_eq!(movie.height, Some(480));
        let page = page::render("a.mov", &movie, false);
        assert!(page.contains("width: 640"), "{page}");
    }

    #[test]
    fn an_ispe_sets_width_and_height() {
        let bytes = with_ftyp(b"heic", &meta_ispe(4032, 3024));
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.format, "heic");
        assert_eq!(movie.width, Some(4032));
        assert_eq!(movie.height, Some(3024));
        assert_eq!(movie.video, 0);
        assert_eq!(movie.audio, 0);
        let page = page::render("a.heic", &movie, false);
        assert!(page.contains("format: heic"), "{page}");
        assert!(page.contains("width: 4032"), "{page}");
        assert!(page.contains("height: 3024"), "{page}");
        let json = page::render_json("a.heic", &movie);
        assert!(json.contains(r#""width":4032"#), "{json}");
        assert!(json.contains(r#""height":3024"#), "{json}");
    }

    #[test]
    fn handlers_and_codecs_are_recorded() {
        let video = {
            let mut body = tkhd(0, 320 << 16, 240 << 16);
            let mut mdia = hdlr(b"vide");
            let minf = box_of(b"minf", &box_of(b"stbl", &stsd(b"avc1")));
            mdia.extend(minf);
            body.extend(box_of(b"mdia", &mdia));
            box_of(b"trak", &body)
        };
        let audio = {
            let mut mdia = hdlr(b"soun");
            let minf = box_of(b"minf", &box_of(b"stbl", &stsd(b"mp4a")));
            mdia.extend(minf);
            box_of(b"trak", &box_of(b"mdia", &mdia))
        };
        let mut moov = mvhd(0, 1000, 50);
        moov.extend(video);
        moov.extend(audio);
        let movie = parse(&with_ftyp(b"isom", &box_of(b"moov", &moov))).unwrap();
        assert_eq!(movie.tracks, 2);
        assert_eq!(movie.video, 1);
        assert_eq!(movie.audio, 1);
        assert_eq!(movie.codecs, vec!["avc1".to_string(), "mp4a".to_string()]);
        assert_eq!(movie.width, Some(320));
        assert_eq!(movie.height, Some(240));
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("video: 1"), "{page}");
        assert!(page.contains("audio: 1"), "{page}");
        assert!(page.contains("avc1"), "{page}");
        assert!(page.contains("mp4a"), "{page}");
        let json = page::render_json("a.mp4", &movie);
        assert!(json.contains(r#""codecs":["avc1","mp4a"]"#), "{json}");
        assert!(json.contains(r#""video":1"#), "{json}");
        assert!(json.contains(r#""audio":1"#), "{json}");
    }

    #[test]
    fn mdat_does_not_hold_tracks() {
        let fake = box_of(b"trak", &[]);
        let mdat = box_of(b"mdat", &fake);
        let movie = parse(&with_ftyp(b"isom", &mdat)).unwrap();
        assert_eq!(movie.tracks, 0);
        assert!(!movie.more);
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("tracks: 0"), "{page}");
    }

    #[test]
    fn a_truncated_ftyp_returns_an_error() {
        assert!(!is_isobmff(b""));
        assert!(!is_isobmff(b"ftyp"));
        assert_eq!(parse(b"").unwrap_err(), "not an isobmff file");
        let mut short = vec![0, 0, 0, 16];
        short.extend_from_slice(b"ftyp");
        short.extend_from_slice(b"iso");
        assert_eq!(short.len(), 11);
        assert!(!is_isobmff(&short));

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&64u32.to_be_bytes());
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(b"isom");
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(bytes.len(), 16);
        assert!(bytes.len() < 64);
        assert!(is_isobmff(&bytes));
        assert!(parse(&bytes).is_err());

        let mut wide = Vec::new();
        wide.extend_from_slice(&1u32.to_be_bytes());
        wide.extend_from_slice(b"ftyp");
        wide.extend_from_slice(&8u64.to_be_bytes());
        assert!(is_isobmff(&wide));
        assert!(parse(&wide).unwrap_err().contains("too small"));
    }

    #[test]
    fn a_huge_box_size_does_not_panic() {
        let mut bytes = ftyp(b"isom", 0, &[]);
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(b"mdat");
        let movie = parse(&bytes).unwrap();
        assert!(movie.more);
        assert_eq!(movie.format, "mp4");
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("format: mp4"), "{page}");

        let mut wide = ftyp(b"isom", 0, &[]);
        wide.extend_from_slice(&1u32.to_be_bytes());
        wide.extend_from_slice(b"mdat");
        wide.extend_from_slice(&u64::MAX.to_be_bytes());
        let movie = parse(&wide).unwrap();
        assert!(movie.more);
        let _ = page::render("b.mp4", &movie, false);

        let mut only = Vec::new();
        only.extend_from_slice(&u32::MAX.to_be_bytes());
        only.extend_from_slice(b"ftyp");
        only.extend_from_slice(b"isom");
        only.extend_from_slice(&0u32.to_be_bytes());
        assert!(is_isobmff(&only));
        assert!(parse(&only).is_err());

        let mut payload = vec![0u8; 8];
        payload[4..8].copy_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&u32::MAX.to_be_bytes());
        payload.extend_from_slice(b"avc1");
        let stsd = box_of(b"stsd", &payload);
        let stbl = box_of(b"stbl", &stsd);
        let minf = box_of(b"minf", &stbl);
        let mdia = box_of(b"mdia", &minf);
        let trak = box_of(b"trak", &mdia);
        let moov = box_of(b"moov", &trak);
        let movie = parse(&with_ftyp(b"isom", &moov)).unwrap();
        assert!(movie.codecs.is_empty());
        assert!(movie.more);
        assert_eq!(movie.tracks, 1);
        let _ = page::render("c.mp4", &movie, false);
    }

    #[test]
    fn a_wide_header_reads_the_major_brand() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"avif");
        payload.extend_from_slice(&0u32.to_be_bytes());
        let total = 16 + payload.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(&(total as u64).to_be_bytes());
        bytes.extend_from_slice(&payload);
        assert!(is_isobmff(&bytes));
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.format, "avif");
        assert_eq!(movie.brand, "avif");
        assert!(!movie.more);
        let page = page::render("a.avif", &movie, false);
        assert!(page.contains("format: avif"), "{page}");
    }

    #[test]
    fn a_later_bad_size_sets_more() {
        let mut bytes = ftyp(b"isom", 0, &[]);
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(b"free");
        bytes.extend(box_of(b"trak", &[]));
        let movie = parse(&bytes).unwrap();
        assert!(movie.more);
        assert_eq!(movie.tracks, 0);
        assert_eq!(movie.format, "mp4");
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("more: true"), "{page}");

        let mut tail = ftyp(b"isom", 0, &[]);
        tail.push(0xff);
        let movie = parse(&tail).unwrap();
        assert!(movie.more);
        let _ = page::render("b.mp4", &movie, false);
    }

    #[test]
    fn a_zero_size_box_ends_at_the_parent_end() {
        let mvhd = mvhd(0, 1000, 50);
        let mut bytes = ftyp(b"qt  ", 0, &[]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"moov");
        bytes.extend_from_slice(&mvhd);
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.format, "mov");
        assert_eq!(movie.timescale, Some(1000));
        assert_eq!(movie.duration, Some(50));
        assert!(!movie.more);
        let page = page::render("a.mov", &movie, false);
        assert!(page.contains("format: mov"), "{page}");
        assert!(page.contains("duration: 50"), "{page}");
    }

    #[test]
    fn compatible_brands_stop_at_32() {
        let brands: Vec<[u8; 4]> = (0..33)
            .map(|index| {
                let mut brand = *b"aa00";
                brand[2] = b'0' + u8::try_from(index / 10).unwrap();
                brand[3] = b'0' + u8::try_from(index % 10).unwrap();
                brand
            })
            .collect();
        let bytes = ftyp(b"isom", 2, &brands);
        let movie = parse(&bytes).unwrap();
        assert_eq!(movie.brands.len(), 32);
        assert_eq!(movie.brands[0], "aa00");
        assert_eq!(movie.minor, 2);
        assert!(movie.more);
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("aa00"), "{page}");
        assert!(!page.contains("aa32"), "{page}");
        let json = page::render_json("a.mp4", &movie);
        assert!(json.contains(r#""more":true"#), "{json}");
    }

    #[test]
    fn codecs_stop_at_eight() {
        let mut body = Vec::new();
        for index in 0..9 {
            let mut codec = *b"c000";
            codec[3] = b'0' + u8::try_from(index).unwrap();
            let minf = box_of(b"minf", &box_of(b"stbl", &stsd(&codec)));
            let mdia = box_of(b"mdia", &minf);
            body.extend(box_of(b"trak", &mdia));
        }
        let movie = parse(&with_ftyp(b"mp42", &box_of(b"moov", &body))).unwrap();
        assert_eq!(movie.format, "mp4");
        assert_eq!(movie.tracks, 9);
        assert_eq!(movie.codecs.len(), 8);
        assert_eq!(movie.codecs[0], "c000");
        assert_eq!(movie.codecs[7], "c007");
        assert!(movie.more);
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("c007"), "{page}");
        assert!(!page.contains("c008"), "{page}");
    }

    #[test]
    fn a_deep_nest_stops_at_depth_eight() {
        let shallow = parse(&wrapped_trak(8)).unwrap();
        assert_eq!(shallow.tracks, 1);
        assert!(!shallow.more);
        let page = page::render("a.mp4", &shallow, false);
        assert!(page.contains("tracks: 1 "), "{page}");

        let deep = parse(&wrapped_trak(9)).unwrap();
        assert_eq!(deep.tracks, 0);
        assert!(deep.more);
        let page = page::render("b.mp4", &deep, false);
        assert!(page.contains("more: true"), "{page}");
    }

    fn wrapped_trak(moov_count: usize) -> Vec<u8> {
        let mut body = box_of(b"trak", &[]);
        for _ in 0..moov_count {
            body = box_of(b"moov", &body);
        }
        with_ftyp(b"isom", &body)
    }

    #[test]
    fn the_walk_stops_at_the_box_cap() {
        let free = box_of(b"free", &[]);
        let mut exact = ftyp(b"isom", 0, &[]);
        for _ in 0..BOX_CAP - 1 {
            exact.extend_from_slice(&free);
        }
        let movie = parse(&exact).unwrap();
        assert!(!movie.more);
        let _ = page::render("exact.mp4", &movie, false);

        let mut extra = ftyp(b"isom", 0, &[]);
        for _ in 0..BOX_CAP {
            extra.extend_from_slice(&free);
        }
        let movie = parse(&extra).unwrap();
        assert!(movie.more);
        assert_eq!(movie.format, "mp4");
        let page = page::render("a.mp4", &movie, false);
        assert!(page.contains("more: true"), "{page}");
    }
}
