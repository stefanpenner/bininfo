/*
---
why: This file reads one Apple disk image trailer.
uses: bininfo
how: bininfo calls this file when the bytes end in a koly trailer.
Enter reads one part and does not read the next file.
A zlib block stops at 1 MiB.
An APFS part states that this reader does not list its files.
A watch stops that read between blocks.
---
*/

//! One UDIF disk image. The `koly` trailer is the record.
//! Enter reads one part. A zlib block stops at 1 MiB.
//! An APFS part states that this reader does not list its files.

pub mod page;

mod hfs;

const TRAILER: usize = 512;
const NAME_CAP: usize = 32;
const TEXT_CAP: usize = 256;
const PLIST_WINDOW: usize = 1024 * 1024;
const PART_CAP: usize = 32;
const CHUNK_CAP: usize = 4096;
const MISH_CAP: usize = 1 << 20;
const INFLATE_CAP: usize = 1 << 20;
const INPUT_CAP: usize = 8 << 20;
const MISH_HEAD: usize = 204;
const CHUNK_LEN: usize = 40;

/// One mapped chunk inside a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub kind: u32,
    pub sector: u64,
    pub count: u64,
    pub offset: u64,
    pub length: u64,
}

/// One blkx partition. `chunks` name the blocks and do not hold their bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub name: String,
    pub chunks: Vec<Chunk>,
}

/// One Apple disk image. Numbers come from the `koly` trailer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub variant: [u8; 4],
    pub version: u32,
    pub flags: u32,
    pub sectors: u64,
    pub segment: u32,
    pub segments: u32,
    pub data_offset: u64,
    pub data_length: u64,
    pub xml_offset: u64,
    pub xml_length: u64,
    pub checksum: u32,
    pub names: Vec<String>,
    pub parts: Vec<Part>,
}

/// True when the last 512 bytes are a version-4 `koly` trailer.
pub fn is_dmg(bytes: &[u8]) -> bool {
    let Some(trailer) = trailer(bytes) else {
        return false;
    };
    trailer[..4] == *b"koly" && u32_be(trailer, 4) == Some(4) && u32_be(trailer, 8) == Some(512)
}

/// Read the trailer, the partition names, and the block map.
/// This function does not inflate a block.
pub fn parse(bytes: &[u8]) -> Result<Image, String> {
    if !is_dmg(bytes) {
        return Err("not a dmg file".into());
    }
    let raw = trailer(bytes).ok_or("file ends before the dmg trailer")?;
    let xml_offset = u64_be(raw, 216).ok_or("file ends before the dmg trailer")?;
    let xml_length = u64_be(raw, 224).ok_or("file ends before the dmg trailer")?;
    let names = plist_names(bytes, xml_offset, xml_length)?;
    let fork = u64_be(raw, 24).ok_or("file ends before the dmg trailer")?;
    let parts = plist_parts(bytes, xml_offset, xml_length, fork);
    let mut variant = [0u8; 4];
    variant.copy_from_slice(
        raw.get(488..492)
            .ok_or("file ends before the dmg trailer")?,
    );
    Ok(Image {
        variant,
        version: need_u32(raw, 4)?,
        flags: need_u32(raw, 12)?,
        sectors: need_u64(raw, 492)?,
        segment: need_u32(raw, 56)?,
        segments: need_u32(raw, 60)?,
        data_offset: need_u64(raw, 24)?,
        data_length: need_u64(raw, 32)?,
        xml_offset,
        xml_length,
        checksum: need_u32(raw, 352)?,
        names,
        parts,
    })
}

/// Printable fourcc, or the hex word when a byte is not text.
pub fn fourcc(variant: &[u8; 4]) -> String {
    if variant.iter().all(|byte| (0x20..0x7f).contains(byte)) {
        variant.iter().map(|byte| *byte as char).collect()
    } else {
        format!("0x{:X}", u32::from_be_bytes(*variant))
    }
}

/// Image variant word. `None` means the fourcc has no word here.
pub fn variant_name(variant: &[u8; 4]) -> Option<&'static str> {
    Some(match variant {
        b"UDZO" => "zlib",
        b"UDBZ" => "bzip2",
        b"ULFO" => "lzfse",
        b"ULMO" => "lzma",
        b"UDCO" => "adc",
        b"UDRO" => "read-only",
        b"UDRW" => "read-write",
        b"UDTO" => "dvd",
        _ => return None,
    })
}

/// Master checksum word. `None` means the number has no word here.
pub fn checksum_name(kind: u32) -> Option<&'static str> {
    match kind {
        0 => Some("none"),
        2 => Some("crc32"),
        _ => None,
    }
}

fn trailer(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < TRAILER {
        return None;
    }
    bytes.get(bytes.len() - TRAILER..)
}

fn plist_names(bytes: &[u8], offset: u64, length: u64) -> Result<Vec<String>, String> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let start = usize::try_from(offset).map_err(|_| "dmg resource plist is outside this file")?;
    let len = usize::try_from(length).map_err(|_| "dmg resource plist is outside this file")?;
    let end = start
        .checked_add(len)
        .ok_or("dmg resource plist is outside this file")?;
    if end > bytes.len() {
        return Err("dmg resource plist is outside this file".into());
    }
    let window_end = end.min(start.saturating_add(PLIST_WINDOW));
    Ok(scan_names(&bytes[start..window_end]))
}

fn scan_names(bytes: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = 0;
    while names.len() < NAME_CAP {
        let name_key = find_sub(bytes, b"<key>Name</key>", cursor);
        let cf_key = find_sub(bytes, b"<key>CFName</key>", cursor);
        let at = match (name_key, cf_key) {
            (Some(left), Some(right)) => left.min(right),
            (Some(left), None) => left,
            (None, Some(right)) => right,
            (None, None) => break,
        };
        let key_len = if bytes[at..].starts_with(b"<key>CFName</key>") {
            17
        } else {
            15
        };
        let rest = at + key_len;
        let Some(string_at) = find_sub(bytes, b"<string>", rest) else {
            break;
        };
        if let Some(next_key) = find_sub(bytes, b"<key>", rest) {
            if next_key < string_at {
                cursor = rest;
                continue;
            }
        }
        let text_at = string_at + b"<string>".len();
        let Some(end) = find_sub(bytes, b"</string>", text_at) else {
            break;
        };
        if end - text_at <= TEXT_CAP {
            if let Ok(text) = std::str::from_utf8(&bytes[text_at..end]) {
                let text = text.trim();
                if !text.is_empty() && !names.iter().any(|name| name == text) {
                    names.push(text.to_string());
                }
            }
        }
        cursor = end + b"</string>".len();
    }
    names
}

pub(crate) enum Step {
    Page(String),
    Body(Vec<u8>),
    Cap,
    Miss,
    Stop,
}

/// The page for one part, or the part bytes when the part is a known file.
pub(crate) fn view_part(bytes: &[u8], part: &Part, color: bool, watch: &crate::Watch) -> Step {
    let mut disk = Disk::new(bytes, &part.chunks, watch);
    match hfs::list(&mut |at, len| disk.read(at, len)) {
        Ok((files, more)) => Step::Page(hfs::page(&part.name, &files, more, color)),
        Err(hfs::Fault::Miss) => {
            let mut probe = Disk::new(bytes, &part.chunks, watch);
            match probe.read(0, 512) {
                Ok(head) if head.get(32..36) == Some(b"NXSB".as_slice()) => {
                    Step::Page(apfs_page(&part.name))
                }
                Err(hfs::Fault::Miss) | Ok(_) => {
                    let mut plain = Disk::new(bytes, &part.chunks, watch);
                    match plain.read(0, INFLATE_CAP) {
                        Ok(body) => Step::Body(body),
                        Err(fault) => fault_step(fault, &part.name),
                    }
                }
                Err(fault) => fault_step(fault, &part.name),
            }
        }
        Err(fault) => fault_step(fault, &part.name),
    }
}

/// The bytes of one file in an HFS part.
pub(crate) fn view_file(bytes: &[u8], part: &Part, name: &str, watch: &crate::Watch) -> Step {
    let mut disk = Disk::new(bytes, &part.chunks, watch);
    match hfs::file_bytes(&mut |at, len| disk.read(at, len), name) {
        Ok(body) => Step::Body(body),
        Err(fault) => fault_step(fault, name),
    }
}

fn fault_step(fault: hfs::Fault, name: &str) -> Step {
    match fault {
        hfs::Fault::Cap => Step::Cap,
        hfs::Fault::Block(word) => Step::Page(block_page(name, word)),
        hfs::Fault::Miss => Step::Miss,
        hfs::Fault::Stop => Step::Stop,
    }
}

fn block_page(name: &str, word: &str) -> String {
    format!("file: {name}\nreason: This block uses {word}.\n")
}

fn apfs_page(name: &str) -> String {
    format!(
        "file: {name}\nreason: This part is an APFS volume. This reader does not list its files.\n"
    )
}

struct Disk<'a> {
    bytes: &'a [u8],
    chunks: &'a [Chunk],
    watch: &'a crate::Watch,
    /// Byte 0 of this part. A blkx sector is a disk address.
    origin: u64,
    left: usize,
    cache: Vec<Option<Vec<u8>>>,
}

impl<'a> Disk<'a> {
    fn new(bytes: &'a [u8], chunks: &'a [Chunk], watch: &'a crate::Watch) -> Self {
        let origin = chunks
            .iter()
            .map(|chunk| chunk.sector)
            .min()
            .unwrap_or(0)
            .saturating_mul(512);
        Self {
            bytes,
            chunks,
            watch,
            origin,
            left: INFLATE_CAP,
            cache: vec![None; chunks.len()],
        }
    }

    fn read(&mut self, at: u64, len: usize) -> Result<Vec<u8>, hfs::Fault> {
        if self.watch.stopped() {
            return Err(hfs::Fault::Stop);
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > self.left {
            return Err(hfs::Fault::Cap);
        }
        let mut out = vec![0u8; len];
        let mut filled = 0usize;
        while filled < len {
            if self.watch.stopped() {
                return Err(hfs::Fault::Stop);
            }
            let pos = self
                .origin
                .checked_add(at)
                .and_then(|base| base.checked_add(filled as u64))
                .ok_or(hfs::Fault::Miss)?;
            let Some(index) = find_chunk(self.chunks, pos) else {
                if filled == 0 {
                    return Err(hfs::Fault::Miss);
                }
                out.truncate(filled);
                self.left -= filled;
                return Ok(out);
            };
            let kind = self.chunks[index].kind;
            let sector = self.chunks[index].sector;
            let count = self.chunks[index].count;
            let offset = self.chunks[index].offset;
            let length = self.chunks[index].length;
            let base = sector.checked_mul(512).ok_or(hfs::Fault::Miss)?;
            let into = usize::try_from(pos.checked_sub(base).ok_or(hfs::Fault::Miss)?)
                .map_err(|_| hfs::Fault::Miss)?;
            match kind {
                0 | 2 => {
                    let room = chunk_bytes(count).ok_or(hfs::Fault::Miss)?;
                    if into >= room {
                        return Err(hfs::Fault::Miss);
                    }
                    filled += (room - into).min(len - filled);
                }
                1 => {
                    let raw = slice_file(self.bytes, offset, length)?;
                    let room = raw.len().saturating_sub(into);
                    if room == 0 {
                        return Err(hfs::Fault::Miss);
                    }
                    let take = room.min(len - filled);
                    out[filled..filled + take].copy_from_slice(&raw[into..into + take]);
                    self.watch.add(take as u64);
                    filled += take;
                }
                0x8000_0005 => {
                    let plain = self.inflate(index)?;
                    let room = plain.len().saturating_sub(into);
                    if room == 0 {
                        return Err(hfs::Fault::Miss);
                    }
                    let take = room.min(len - filled);
                    out[filled..filled + take].copy_from_slice(&plain[into..into + take]);
                    filled += take;
                }
                kind => return Err(hfs::Fault::Block(block_word(kind))),
            }
        }
        self.left -= filled;
        Ok(out)
    }

    fn inflate(&mut self, index: usize) -> Result<Vec<u8>, hfs::Fault> {
        if self.watch.stopped() {
            return Err(hfs::Fault::Stop);
        }
        if let Some(hit) = &self.cache[index] {
            return Ok(hit.clone());
        }
        let offset = self.chunks[index].offset;
        let length = self.chunks[index].length;
        let count = self.chunks[index].count;
        if length > INPUT_CAP as u64 {
            return Err(hfs::Fault::Cap);
        }
        let plain_len = chunk_bytes(count).ok_or(hfs::Fault::Miss)?;
        if plain_len > INFLATE_CAP {
            return Err(hfs::Fault::Cap);
        }
        let raw = slice_file(self.bytes, offset, length)?;
        let plain = crate::certs::inflate_zlib(raw, plain_len).ok_or(hfs::Fault::Miss)?;
        self.watch.add(plain.len() as u64);
        self.cache[index] = Some(plain.clone());
        Ok(plain)
    }
}

fn find_chunk(chunks: &[Chunk], at: u64) -> Option<usize> {
    let sector = at / 512;
    chunks.iter().position(|chunk| {
        let end = chunk.sector.saturating_add(chunk.count);
        sector >= chunk.sector
            && sector < end
            && chunk.kind != 0xffff_ffff
            && chunk.kind != 0x7fff_fffe
    })
}

fn chunk_bytes(count: u64) -> Option<usize> {
    usize::try_from(count.checked_mul(512)?).ok()
}

fn slice_file(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8], hfs::Fault> {
    let at = usize::try_from(offset).map_err(|_| hfs::Fault::Miss)?;
    let len = usize::try_from(length).map_err(|_| hfs::Fault::Cap)?;
    if len > INPUT_CAP {
        return Err(hfs::Fault::Cap);
    }
    let end = at.checked_add(len).ok_or(hfs::Fault::Miss)?;
    bytes.get(at..end).ok_or(hfs::Fault::Miss)
}

fn block_word(kind: u32) -> &'static str {
    match kind {
        0x8000_0004 => "adc",
        0x8000_0006 => "bzip2",
        0x8000_0007 => "lzfse",
        0x8000_0008 => "lzma",
        _ => "an unknown method",
    }
}

fn plist_parts(bytes: &[u8], offset: u64, length: u64, fork: u64) -> Vec<Part> {
    if length == 0 {
        return Vec::new();
    }
    let Ok(start) = usize::try_from(offset) else {
        return Vec::new();
    };
    let Ok(len) = usize::try_from(length) else {
        return Vec::new();
    };
    let Some(end) = start.checked_add(len) else {
        return Vec::new();
    };
    if end > bytes.len() {
        return Vec::new();
    }
    let window_end = end.min(start.saturating_add(PLIST_WINDOW));
    scan_parts(&bytes[start..window_end], fork)
}

fn scan_parts(bytes: &[u8], fork: u64) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut cursor = 0usize;
    let mut label: Option<String> = None;
    while parts.len() < PART_CAP {
        let name_at = find_sub(bytes, b"<key>Name</key>", cursor);
        let cf_at = find_sub(bytes, b"<key>CFName</key>", cursor);
        let data_at = find_sub(bytes, b"<data>", cursor);
        let next = match (name_at, cf_at, data_at) {
            (None, None, None) => break,
            _ => [name_at, cf_at, data_at]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(cursor),
        };
        if data_at == Some(next) {
            let text_at = next + b"<data>".len();
            let Some(end) = find_sub(bytes, b"</data>", text_at) else {
                break;
            };
            if let Some(raw) = b64(&bytes[text_at..end]) {
                if let Some(part) = mish_part(&raw, label.take(), fork) {
                    parts.push(part);
                }
            }
            label = None;
            cursor = end + b"</data>".len();
            continue;
        }
        let key_len = if cf_at == Some(next) { 17 } else { 15 };
        if let Some((text, next_at)) = xml_string(bytes, next + key_len) {
            if !text.is_empty() {
                label = Some(text);
            }
            cursor = next_at;
        } else {
            break;
        }
    }
    parts
}

fn xml_string(bytes: &[u8], from: usize) -> Option<(String, usize)> {
    let start = find_sub(bytes, b"<string>", from)?;
    if let Some(key) = find_sub(bytes, b"<key>", from) {
        if key < start {
            return None;
        }
    }
    let text_at = start + b"<string>".len();
    let end = find_sub(bytes, b"</string>", text_at)?;
    if end - text_at > TEXT_CAP {
        return Some((String::new(), end + b"</string>".len()));
    }
    let text = std::str::from_utf8(&bytes[text_at..end])
        .ok()?
        .trim()
        .to_string();
    Some((text, end + b"</string>".len()))
}

fn mish_part(raw: &[u8], label: Option<String>, fork: u64) -> Option<Part> {
    if raw.len() < MISH_HEAD || raw.get(..4) != Some(b"mish".as_slice()) {
        return None;
    }
    let base_sector = u64_at(raw, 8)?;
    let data_at = u64_at(raw, 0x18)?;
    let origin = fork.checked_add(data_at)?;
    let mut chunks = Vec::new();
    let mut at = MISH_HEAD;
    while at + CHUNK_LEN <= raw.len() && chunks.len() < CHUNK_CAP {
        let kind = u32_at(raw, at)?;
        let sector = base_sector.checked_add(u64_at(raw, at + 8)?)?;
        let count = u64_at(raw, at + 16)?;
        let offset = origin.checked_add(u64_at(raw, at + 24)?)?;
        let length = u64_at(raw, at + 32)?;
        if kind != 0xffff_ffff && kind != 0x7fff_fffe {
            chunks.push(Chunk {
                kind,
                sector,
                count,
                offset,
                length,
            });
        }
        at += CHUNK_LEN;
    }
    if chunks.is_empty() {
        return None;
    }
    let name = label
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "part".to_string());
    Some(Part { name, chunks })
}

fn b64(text: &[u8]) -> Option<Vec<u8>> {
    let mut vals = Vec::new();
    for &byte in text {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        vals.push(value);
        if vals.len() > MISH_CAP {
            return None;
        }
    }
    if vals.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::new();
    let mut index = 0;
    while index + 4 <= vals.len() {
        let n = (u32::from(vals[index]) << 18)
            | (u32::from(vals[index + 1]) << 12)
            | (u32::from(vals[index + 2]) << 6)
            | u32::from(vals[index + 3]);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        index += 4;
        if out.len() > MISH_CAP {
            return None;
        }
    }
    if index + 2 == vals.len() {
        let n = (u32::from(vals[index]) << 18) | (u32::from(vals[index + 1]) << 12);
        out.push((n >> 16) as u8);
    } else if index + 3 == vals.len() {
        let n = (u32::from(vals[index]) << 18)
            | (u32::from(vals[index + 1]) << 12)
            | (u32::from(vals[index + 2]) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    }
    Some(out)
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    u32_be(bytes, at)
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    u64_be(bytes, at)
}

fn find_sub(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|index| from + index)
}

fn need_u32(bytes: &[u8], at: usize) -> Result<u32, String> {
    u32_be(bytes, at).ok_or_else(|| "file ends before the dmg trailer".into())
}

fn need_u64(bytes: &[u8], at: usize) -> Result<u64, String> {
    u64_be(bytes, at).ok_or_else(|| "file ends before the dmg trailer".into())
}

fn u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    let s = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_be(bytes: &[u8], at: usize) -> Option<u64> {
    let s = bytes.get(at..at + 8)?;
    Some(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[cfg(test)]
fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(xml: &str) -> Vec<u8> {
        let mut bytes = xml.as_bytes().to_vec();
        let mut koly = vec![0u8; TRAILER];
        koly[..4].copy_from_slice(b"koly");
        put_u32(&mut koly, 4, 4);
        put_u32(&mut koly, 8, 512);
        put_u32(&mut koly, 12, 1);
        put_u64(&mut koly, 24, 512);
        put_u64(&mut koly, 32, 100);
        put_u32(&mut koly, 56, 0);
        put_u32(&mut koly, 60, 1);
        put_u64(&mut koly, 216, 0);
        put_u64(&mut koly, 224, xml.len() as u64);
        put_u32(&mut koly, 352, 2);
        koly[488..492].copy_from_slice(b"UDZO");
        put_u64(&mut koly, 492, 2048);
        bytes.extend_from_slice(&koly);
        bytes
    }

    const PLIST: &str = "\
<?xml version=\"1.0\"?>
<plist><dict><key>resource-fork</key><dict><key>blkx</key><array><dict>\
<key>Name</key><string>whole disk</string>\
<key>CFName</key><string>whole disk (Apple_APFS : 1)</string>\
</dict></array></dict></dict></plist>";

    #[test]
    fn a_koly_trailer_names_the_image() {
        let bytes = image(PLIST);
        assert!(is_dmg(&bytes));
        let image = parse(&bytes).unwrap();
        assert_eq!(fourcc(&image.variant), "UDZO");
        assert_eq!(variant_name(&image.variant), Some("zlib"));
        assert_eq!(image.version, 4);
        assert_eq!(image.flags, 1);
        assert_eq!(image.sectors, 2048);
        assert_eq!(image.segment, 0);
        assert_eq!(image.segments, 1);
        assert_eq!(image.data_offset, 512);
        assert_eq!(image.data_length, 100);
        assert_eq!(image.checksum, 2);
        assert_eq!(image.names, ["whole disk", "whole disk (Apple_APFS : 1)"]);
        let page = page::render("a.dmg", &image, false);
        assert!(page.contains("format: dmg"), "{page}");
        assert!(page.contains("variant: UDZO (zlib)"), "{page}");
        assert!(page.contains("sectors: 2048"), "{page}");
        assert!(page.contains("checksum: crc32 (2)"), "{page}");
        assert!(page.contains("whole disk"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        let json = page::render_json("a.dmg", &image);
        assert!(json.contains(r#""format":"dmg""#), "{json}");
        assert!(json.contains(r#""variant_name":"zlib""#), "{json}");
        assert!(!json.contains(r#""kind""#), "{json}");
        assert!(!json.contains(r#""parts""#), "{json}");
        assert!(!page.contains("parts:"), "{page}");
    }

    #[test]
    fn a_disk_image_wins_over_a_zip_end_record() {
        let mut body = String::from("PK");
        body.push('\u{5}');
        body.push('\u{6}');
        body.extend(std::iter::repeat('\0').take(18));
        let bytes = image(&body);
        let file = crate::open(&bytes, false).unwrap();
        let page = crate::render("a.dmg", &file, false, false);
        assert!(page.contains("format: dmg"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        let err = crate::facts("a.dmg", &file, &host()).unwrap_err();
        assert_eq!(err, "no start claim");
    }

    fn host() -> crate::claim::Host {
        crate::claim::Host {
            arch: "aarch64",
            os: "macos",
            version: None,
            pac: true,
        }
    }

    #[test]
    fn a_trailer_without_a_plist_has_no_names() {
        let mut koly = vec![0u8; TRAILER];
        koly[..4].copy_from_slice(b"koly");
        put_u32(&mut koly, 4, 4);
        put_u32(&mut koly, 8, 512);
        koly[488..492].copy_from_slice(b"UDRW");
        let image = parse(&koly).unwrap();
        assert!(image.names.is_empty());
        assert_eq!(variant_name(&image.variant), Some("read-write"));
        assert_eq!(image.xml_length, 0);
    }

    #[test]
    fn hostile_dmg_bytes_return_an_error() {
        assert_eq!(parse(&[0; 100]).unwrap_err(), "not a dmg file");
        let mut bad = vec![0u8; TRAILER];
        bad[..4].copy_from_slice(b"koly");
        put_u32(&mut bad, 4, 3);
        put_u32(&mut bad, 8, 512);
        assert!(!is_dmg(&bad));
        assert_eq!(parse(&bad).unwrap_err(), "not a dmg file");
        let mut huge = vec![0u8; TRAILER];
        huge[..4].copy_from_slice(b"koly");
        put_u32(&mut huge, 4, 4);
        put_u32(&mut huge, 8, 512);
        put_u64(&mut huge, 224, u64::MAX);
        assert_eq!(
            parse(&huge).unwrap_err(),
            "dmg resource plist is outside this file"
        );
    }

    fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn store_one(name: &str, data: &[u8]) -> Vec<u8> {
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&[0u8; 12]);
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name.as_bytes());
        local.extend_from_slice(data);
        let cd_offset = u32::try_from(local.len()).unwrap();
        let local_offset = 0u32;
        let mut central = Vec::new();
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&[0u8; 12]);
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0u8; 12]);
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        let cd_size = u32::try_from(central.len()).unwrap();
        local.extend(central);
        local.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        local.extend_from_slice(&[0u8; 4]);
        local.extend_from_slice(&1u16.to_le_bytes());
        local.extend_from_slice(&1u16.to_le_bytes());
        local.extend_from_slice(&cd_size.to_le_bytes());
        local.extend_from_slice(&cd_offset.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local
    }

    fn jpeg() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 8, 0, 2, 0, 3, 3];
        out.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0, 0xff, 0xd9]);
        out
    }

    fn b64(raw: &[u8]) -> String {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut index = 0;
        while index + 3 <= raw.len() {
            let n = (u32::from(raw[index]) << 16)
                | (u32::from(raw[index + 1]) << 8)
                | u32::from(raw[index + 2]);
            out.push(ALPHA[(n >> 18) as usize] as char);
            out.push(ALPHA[((n >> 12) & 63) as usize] as char);
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
            out.push(ALPHA[(n & 63) as usize] as char);
            index += 3;
        }
        let left = raw.len() - index;
        if left == 1 {
            let n = u32::from(raw[index]) << 16;
            out.push(ALPHA[(n >> 18) as usize] as char);
            out.push(ALPHA[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        } else if left == 2 {
            let n = (u32::from(raw[index]) << 16) | (u32::from(raw[index + 1]) << 8);
            out.push(ALPHA[(n >> 18) as usize] as char);
            out.push(ALPHA[((n >> 12) & 63) as usize] as char);
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        out
    }

    fn chunk(kind: u32, sector: u64, count: u64, offset: u64, length: u64) -> [u8; 40] {
        let mut row = [0u8; 40];
        row[..4].copy_from_slice(&kind.to_be_bytes());
        row[8..16].copy_from_slice(&sector.to_be_bytes());
        row[16..24].copy_from_slice(&count.to_be_bytes());
        row[24..32].copy_from_slice(&offset.to_be_bytes());
        row[32..].copy_from_slice(&length.to_be_bytes());
        row
    }

    fn mish(rows: &[[u8; 40]]) -> Vec<u8> {
        let mut raw = vec![0u8; MISH_HEAD + rows.len() * CHUNK_LEN];
        raw[..4].copy_from_slice(b"mish");
        for (index, row) in rows.iter().enumerate() {
            let at = MISH_HEAD + index * CHUNK_LEN;
            raw[at..at + CHUNK_LEN].copy_from_slice(row);
        }
        raw
    }

    fn part_xml(name: &str, cf: &str, data: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><plist><dict><key>resource-fork</key><dict>\
<key>blkx</key><array><dict>\
<key>Name</key><string>{name}</string>\
<key>CFName</key><string>{cf}</string>\
<data>{data}</data>\
</dict></array></dict></dict></plist>"
        )
    }

    fn layout(payload: &[u8], xml: &str) -> Vec<u8> {
        let mut bytes = payload.to_vec();
        let xml_at = bytes.len() as u64;
        bytes.extend_from_slice(xml.as_bytes());
        let mut koly = vec![0u8; TRAILER];
        koly[..4].copy_from_slice(b"koly");
        put_u32(&mut koly, 4, 4);
        put_u32(&mut koly, 8, 512);
        put_u32(&mut koly, 12, 1);
        put_u64(&mut koly, 24, 0);
        put_u64(&mut koly, 32, payload.len() as u64);
        put_u32(&mut koly, 56, 0);
        put_u32(&mut koly, 60, 1);
        put_u64(&mut koly, 216, xml_at);
        put_u64(&mut koly, 224, xml.len() as u64);
        put_u32(&mut koly, 352, 2);
        koly[488..492].copy_from_slice(b"UDZO");
        put_u64(&mut koly, 492, 2048);
        bytes.extend_from_slice(&koly);
        bytes
    }

    fn adler32(data: &[u8]) -> u32 {
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

    fn zlib_store(plain: &[u8]) -> Vec<u8> {
        let len = u16::try_from(plain.len()).unwrap();
        let mut out = vec![0x78, 0x01, 0x01];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(plain);
        out.extend_from_slice(&adler32(plain).to_be_bytes());
        out
    }

    /// Eight 512-byte blocks. The header, catalog, and file use fixed offsets.
    fn hfs_volume(photo: &[u8]) -> Vec<u8> {
        let mut vol = vec![0u8; 8 * 512];
        put_u16(&mut vol, 1024, 0x482b);
        put_u16(&mut vol, 1026, 4);
        put_u32(&mut vol, 1024 + 40, 512);
        put_u32(&mut vol, 1024 + 288, 4);
        put_u32(&mut vol, 1024 + 292, 2);
        vol[2048 + 8] = 1;
        put_u32(&mut vol, 2048 + 24, 1);
        put_u16(&mut vol, 2048 + 32, 512);
        vol[2560 + 8] = 0xff;
        put_u16(&mut vol, 2560 + 10, 1);
        let rec = 2560 + 14;
        let units: Vec<u16> = "photo.jpg".encode_utf16().collect();
        let key_len = 6 + units.len() * 2;
        put_u16(&mut vol, rec, u16::try_from(key_len).unwrap());
        put_u32(&mut vol, rec + 2, 2);
        put_u16(&mut vol, rec + 6, u16::try_from(units.len()).unwrap());
        for (index, unit) in units.iter().enumerate() {
            put_u16(&mut vol, rec + 8 + index * 2, *unit);
        }
        let body = rec + 2 + key_len;
        put_u16(&mut vol, body, 2);
        put_u64(&mut vol, body + 88, photo.len() as u64);
        put_u32(&mut vol, body + 104, 6);
        put_u32(&mut vol, body + 108, 1);
        put_u16(&mut vol, 2560 + 512 - 2, 14);
        vol[3072..3072 + photo.len()].copy_from_slice(photo);
        vol
    }

    #[test]
    fn an_hfs_part_stays_closed_until_enter() {
        let photo = jpeg();
        let vol = hfs_volume(&photo);
        let map = mish(&[chunk(1, 0, 8, 0, vol.len() as u64)]);
        let xml = part_xml("whole disk", "disk (Apple_HFS : 4)", &b64(&map));
        let bytes = layout(&vol, &xml);
        let image = parse(&bytes).unwrap();
        assert_eq!(image.names, ["whole disk", "disk (Apple_HFS : 4)"]);
        assert_eq!(image.parts.len(), 1);
        assert_eq!(image.parts[0].name, "disk (Apple_HFS : 4)");
        let file = crate::open(&bytes, false).unwrap();
        let page = crate::render("a.dmg", &file, false, false);
        assert!(page.contains("format: dmg"), "{page}");
        assert!(page.contains("disk (Apple_HFS : 4)"), "{page}");
        assert!(page.contains("whole disk"), "{page}");
        assert!(page.contains("blocks: 1"), "{page}");
        assert!(!page.contains("photo.jpg"), "{page}");
        assert!(!page.contains("format: hfs"), "{page}");
        assert!(!page.contains("format: jpeg"), "{page}");
        let part = "disk (Apple_HFS : 4)";
        let listed = crate::step(&bytes, &[part], false, false).unwrap();
        assert!(listed.contains("format: hfs"), "{listed}");
        assert!(listed.contains("photo.jpg"), "{listed}");
        assert!(!listed.contains("format: jpeg"), "{listed}");
        let opened = crate::step(&bytes, &[part, "photo.jpg"], false, false).unwrap();
        assert!(opened.contains("format: jpeg"), "{opened}");
        assert!(opened.contains("width: 3"), "{opened}");
        assert!(crate::step(&bytes, &[part, "missing.jpg"], false, false).is_none());
        let zip = store_one("note.jpg", &photo);
        let zipped = layout(
            &hfs_volume(&zip),
            &part_xml(
                "whole disk",
                "disk (Apple_HFS : 4)",
                &b64(&mish(&[chunk(1, 0, 8, 0, 4096)])),
            ),
        );
        let held = crate::step(&zipped, &[part, "photo.jpg"], false, false).unwrap();
        assert!(held.contains("format: zip"), "{held}");
        assert!(!held.contains("format: jpeg"), "{held}");
        let note = crate::step(&zipped, &[part, "photo.jpg", "note.jpg"], false, false).unwrap();
        assert!(note.contains("format: jpeg"), "{note}");
        assert!(note.contains("width: 3"), "{note}");
        let json = page::render_json("a.dmg", &image);
        assert!(json.contains(r#""parts""#), "{json}");
        assert!(json.contains("disk (Apple_HFS : 4)"), "{json}");
    }

    #[test]
    fn a_zlib_part_inflates_on_enter() {
        let mut plain = jpeg();
        plain.resize(512, 0);
        let stored = zlib_store(&plain);
        let map = mish(&[chunk(0x8000_0005, 0, 1, 0, stored.len() as u64)]);
        let bytes = layout(&stored, &part_xml("raw", "photo part", &b64(&map)));
        let file = crate::open(&bytes, false).unwrap();
        let page = crate::render("a.dmg", &file, false, false);
        assert!(page.contains("format: dmg"), "{page}");
        assert!(!page.contains("format: jpeg"), "{page}");
        let one = crate::step(&bytes, &["photo part"], false, false).unwrap();
        assert!(one.contains("format: jpeg"), "{one}");
        assert!(one.contains("width: 3"), "{one}");
    }

    #[test]
    fn an_apfs_part_states_the_limit() {
        let mut vol = vec![0u8; 512];
        vol[32..36].copy_from_slice(b"NXSB");
        let map = mish(&[chunk(1, 0, 1, 0, vol.len() as u64)]);
        let bytes = layout(
            &vol,
            &part_xml("whole disk", "disk (Apple_APFS : 1)", &b64(&map)),
        );
        let page = crate::step(&bytes, &["disk (Apple_APFS : 1)"], false, false).unwrap();
        assert!(page.contains("APFS"), "{page}");
        assert!(page.contains("does not list its files"), "{page}");
        assert!(!page.contains("format: hfs"), "{page}");
    }

    #[test]
    fn hostile_dmg_parts_do_not_panic() {
        let bad = layout(&[], &part_xml("n", "bad", "!!!!"));
        assert!(parse(&bad).unwrap().parts.is_empty());
        let short = layout(&[], &part_xml("n", "short", &b64(b"mish")));
        assert!(parse(&short).unwrap().parts.is_empty());
        let huge = chunk(0, 0, u64::MAX, 0, 0);
        let huge_bytes = layout(&[0u8; 512], &part_xml("n", "huge", &b64(&mish(&[huge]))));
        assert_eq!(parse(&huge_bytes).unwrap().parts.len(), 1);
        assert!(crate::step(&huge_bytes, &["huge"], false, false).is_none());
        let bz = chunk(0x8000_0006, 0, 8, 0, 0);
        let bz_bytes = layout(&[0u8; 4096], &part_xml("n", "bz", &b64(&mish(&[bz]))));
        let page = crate::step(&bz_bytes, &["bz"], false, false).unwrap();
        assert!(page.contains("bzip2"), "{page}");
        assert!(!page.contains("format: hfs"), "{page}");
        assert!(crate::step(&bz_bytes, &["bz", "photo.jpg"], false, false).is_none());
        let odd = chunk(0x11, 0, 8, 0, 0);
        let odd_bytes = layout(&[0u8; 4096], &part_xml("n", "odd", &b64(&mish(&[odd]))));
        let odd_page = crate::step(&odd_bytes, &["odd"], false, false).unwrap();
        assert!(odd_page.contains("an unknown method"), "{odd_page}");
        let past = chunk(1, 0, 1, 1 << 40, 512);
        let past_bytes = layout(&[0u8; 512], &part_xml("n", "past", &b64(&mish(&[past]))));
        assert!(crate::step(&past_bytes, &["past"], false, false).is_none());
        assert!(crate::step(&past_bytes, &["no such part"], false, false).is_none());
    }

    #[test]
    fn a_part_with_a_sector_base_lists_its_files() {
        let photo = jpeg();
        let vol = hfs_volume(&photo);
        let map = mish(&[chunk(1, 40, 8, 0, vol.len() as u64)]);
        let bytes = layout(
            &vol,
            &part_xml("whole disk", "disk (Apple_HFS : 4)", &b64(&map)),
        );
        let listed = crate::step(&bytes, &["disk (Apple_HFS : 4)"], false, false);
        let listed = listed.unwrap();
        assert!(listed.contains("format: hfs"), "{listed}");
        assert!(listed.contains("photo.jpg"), "{listed}");
    }

    fn hfs_disk() -> Vec<u8> {
        let photo = jpeg();
        let vol = hfs_volume(&photo);
        let map = mish(&[chunk(1, 40, 8, 0, vol.len() as u64)]);
        layout(
            &vol,
            &part_xml("whole disk", "disk (Apple_HFS : 4)", &b64(&map)),
        )
    }

    #[test]
    fn a_stopped_watch_reads_no_part() {
        let bytes = hfs_disk();
        let watch = crate::Watch::new();
        watch.stop();
        let page = crate::step_watch(&bytes, &["disk (Apple_HFS : 4)"], false, false, &watch);
        assert!(page.is_none());
        assert_eq!(watch.done(), 0);
    }

    #[test]
    fn a_watch_stops_between_reads() {
        let bytes = hfs_disk();
        let watch = crate::Watch::new();
        watch.cap_at(1);
        let page = crate::step_watch(&bytes, &["disk (Apple_HFS : 4)"], false, false, &watch);
        assert!(page.is_none());
        assert!(watch.stopped());
        assert!(watch.done() >= 1);
    }
}
