/*
---
why: This file names the section or segment that holds a certificate hit.
uses: bininfo
how: The certificate scan calls this file with the same file bytes.
A byte past the last section is named overlay.
---
*/

//! Map a file offset to a section, a segment, or overlay.
//! A PE certificate table and a Mach-O code signature are signer ranges.
//! A NODE_SEA_BLOB section or resource is a sea range.

use crate::elf::header::Class as ElfClass;
use crate::elf::header::Data as ElfData;
use crate::elf::header::Header as ElfHeader;
use crate::macho::header::Class as MachClass;
use crate::macho::header::Data as MachData;
use crate::macho::header::Image;
use crate::pe::header::Header as PeHeader;

const REGION_CAP: usize = 512;

struct Span {
    start: usize,
    end: usize,
    name: String,
}

pub(super) struct Map {
    parsed: bool,
    sections: Vec<Span>,
    segments: Vec<Span>,
    last: usize,
    signer: Vec<(usize, usize)>,
    sea: Vec<(usize, usize)>,
}

impl Map {
    pub(super) fn build(bytes: &[u8]) -> Self {
        let mut map = Self {
            parsed: false,
            sections: Vec::new(),
            segments: Vec::new(),
            last: 0,
            signer: Vec::new(),
            sea: Vec::new(),
        };
        if crate::elf::header::is_elf(bytes) {
            if let Ok(header) = crate::elf::header::parse(bytes) {
                map.parsed = true;
                elf_map(bytes, &header, &mut map);
            }
        } else if crate::macho::header::is_macho(bytes) {
            if let Ok(image) = crate::macho::header::parse(bytes) {
                map.parsed = true;
                macho_map(bytes, &image, &mut map);
            }
        } else if crate::pe::header::is_pe(bytes) {
            if let Ok(header) = crate::pe::header::parse(bytes) {
                map.parsed = true;
                pe_map(bytes, &header, &mut map);
            }
        }
        map
    }

    pub(super) fn place(&self, offset: usize) -> String {
        if !self.parsed {
            return "file".to_string();
        }
        if let Some(name) = shortest(&self.sections, offset) {
            return name;
        }
        if let Some(name) = shortest(&self.segments, offset) {
            return name;
        }
        if offset >= self.last {
            "overlay".to_string()
        } else {
            "header".to_string()
        }
    }

    /// Segments, then sections, as (is_section, name, start, end).
    pub(super) fn spans(&self) -> Vec<(bool, String, usize, usize)> {
        let segs = self.segments.iter().map(|s| (false, s));
        let secs = self.sections.iter().map(|s| (true, s));
        segs.chain(secs)
            .map(|(sec, s)| (sec, s.name.clone(), s.start, s.end))
            .collect()
    }

    pub(super) fn signer(&self, offset: usize) -> bool {
        contains(&self.signer, offset)
    }

    pub(super) fn sea(&self, offset: usize) -> bool {
        contains(&self.sea, offset)
    }

    fn push_section(&mut self, start: usize, end: usize, name: String) {
        if end <= start {
            return;
        }
        self.cover(end);
        if sea_name(&name) {
            self.mark_sea(start, end);
        }
        if self.sections.len() < REGION_CAP {
            self.sections.push(Span { start, end, name });
        }
    }

    fn push_segment(&mut self, start: usize, end: usize, name: String) {
        if end <= start {
            return;
        }
        self.cover(end);
        if sea_name(&name) {
            self.mark_sea(start, end);
        }
        if self.segments.len() < REGION_CAP {
            self.segments.push(Span { start, end, name });
        }
    }

    fn mark_sea(&mut self, start: usize, end: usize) {
        if self.sea.len() < REGION_CAP && end > start {
            self.sea.push((start, end));
        }
    }

    fn mark_signer(&mut self, start: usize, end: usize) {
        if self.signer.len() < REGION_CAP && end > start {
            self.signer.push((start, end));
        }
    }

    fn cover(&mut self, end: usize) {
        if end > self.last {
            self.last = end;
        }
    }

    fn cover_span(&mut self, start: u64, size: u64, len: usize) {
        let Some(start) = usize::try_from(start).ok() else {
            return;
        };
        if start >= len {
            return;
        }
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        self.cover(start.saturating_add(size).min(len));
    }
}

fn contains(ranges: &[(usize, usize)], offset: usize) -> bool {
    ranges
        .iter()
        .any(|(start, end)| offset >= *start && offset < *end)
}

fn shortest(spans: &[Span], offset: usize) -> Option<String> {
    let mut best: Option<&Span> = None;
    for span in spans {
        if offset < span.start || offset >= span.end {
            continue;
        }
        let tighter = best
            .map(|item| span.end - span.start < item.end - item.start)
            .unwrap_or(true);
        if tighter {
            best = Some(span);
        }
    }
    best.map(|span| span.name.clone())
}

fn sea_name(name: &str) -> bool {
    name == "NODE_SEA"
        || name == "NODE_SEA_BLOB"
        || name == "__NODE_SEA_BLOB"
        || name.ends_with("NODE_SEA_BLOB")
}

fn clamp(start: u64, size: u64, len: usize) -> Option<(usize, usize)> {
    let start = usize::try_from(start).ok()?;
    if start >= len || size == 0 {
        return None;
    }
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    Some((start, start.saturating_add(size).min(len)))
}

fn elf_map(bytes: &[u8], header: &ElfHeader, map: &mut Map) {
    let data = header.data;
    let phentsize = header.phentsize as usize;
    let phnum = usize::from(header.phnum).min(REGION_CAP);
    if phentsize >= 32 && header.phnum > 0 {
        map.cover_span(header.phoff, phentsize as u64 * phnum as u64, bytes.len());
        for index in 0..phnum {
            let at = (header.phoff as usize).saturating_add(index.saturating_mul(phentsize));
            if at.saturating_add(phentsize) > bytes.len() {
                break;
            }
            let kind = elf_u32(bytes, at, data).unwrap_or(0);
            let (offset, filesz) = match header.class {
                ElfClass::Elf32 => (
                    u64::from(elf_u32(bytes, at + 4, data).unwrap_or(0)),
                    u64::from(elf_u32(bytes, at + 16, data).unwrap_or(0)),
                ),
                ElfClass::Elf64 => {
                    if phentsize < 48 {
                        continue;
                    }
                    (
                        elf_u64(bytes, at + 8, data).unwrap_or(0),
                        elf_u64(bytes, at + 32, data).unwrap_or(0),
                    )
                }
            };
            if kind == 0 {
                continue;
            }
            if let Some((start, end)) = clamp(offset, filesz, bytes.len()) {
                map.push_segment(start, end, pt_name(kind));
            }
        }
    }
    let shentsize = header.shentsize as usize;
    let shnum = usize::from(header.shnum).min(REGION_CAP);
    if shentsize >= 40 && header.shnum > 0 {
        map.cover_span(header.shoff, shentsize as u64 * shnum as u64, bytes.len());
        let strtab = elf_strtab(bytes, header);
        for index in 0..shnum {
            let at = (header.shoff as usize).saturating_add(index.saturating_mul(shentsize));
            let need = match header.class {
                ElfClass::Elf32 => 24,
                ElfClass::Elf64 => 40,
            };
            if at.saturating_add(need) > bytes.len() {
                break;
            }
            let name_off = elf_u32(bytes, at, data).unwrap_or(0);
            let kind = elf_u32(bytes, at + 4, data).unwrap_or(0);
            let (offset, size) = match header.class {
                ElfClass::Elf32 => (
                    u64::from(elf_u32(bytes, at + 16, data).unwrap_or(0)),
                    u64::from(elf_u32(bytes, at + 20, data).unwrap_or(0)),
                ),
                ElfClass::Elf64 => (
                    elf_u64(bytes, at + 24, data).unwrap_or(0),
                    elf_u64(bytes, at + 32, data).unwrap_or(0),
                ),
            };
            if kind == 0 || kind == 8 {
                continue;
            }
            if let Some((start, end)) = clamp(offset, size, bytes.len()) {
                map.push_section(start, end, elf_name(strtab, name_off));
            }
        }
    }
    let ehsize = match header.class {
        ElfClass::Elf32 => 52,
        ElfClass::Elf64 => 64,
    };
    map.cover(ehsize.min(bytes.len()));
}

fn elf_strtab<'a>(bytes: &'a [u8], header: &ElfHeader) -> &'a [u8] {
    let index = usize::from(header.shstrndx);
    if header.shstrndx == 0xffff || index == 0 || index >= usize::from(header.shnum) {
        return &[];
    }
    let shentsize = header.shentsize as usize;
    let at = (header.shoff as usize).saturating_add(index.saturating_mul(shentsize));
    let (offset, size) = match header.class {
        ElfClass::Elf32 => (
            u64::from(elf_u32(bytes, at + 16, header.data).unwrap_or(0)),
            u64::from(elf_u32(bytes, at + 20, header.data).unwrap_or(0)),
        ),
        ElfClass::Elf64 => (
            elf_u64(bytes, at + 24, header.data).unwrap_or(0),
            elf_u64(bytes, at + 32, header.data).unwrap_or(0),
        ),
    };
    let Some((start, end)) = clamp(offset, size, bytes.len()) else {
        return &[];
    };
    &bytes[start..end]
}

fn elf_name(strtab: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= strtab.len() {
        return "section".to_string();
    }
    let end = strtab[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| start + index)
        .unwrap_or(strtab.len());
    let slice = &strtab[start..end];
    if slice.is_empty() || !slice.iter().all(|byte| byte.is_ascii_graphic()) {
        return "section".to_string();
    }
    String::from_utf8_lossy(slice).into_owned()
}

fn pt_name(kind: u32) -> String {
    match kind {
        1 => "PT_LOAD".to_string(),
        2 => "PT_DYNAMIC".to_string(),
        3 => "PT_INTERP".to_string(),
        4 => "PT_NOTE".to_string(),
        6 => "PT_PHDR".to_string(),
        7 => "PT_TLS".to_string(),
        other => format!("PT_{other}"),
    }
}

fn elf_u32(bytes: &[u8], at: usize, data: ElfData) -> Option<u32> {
    let raw = bytes.get(at..at + 4)?;
    let chunk = [raw[0], raw[1], raw[2], raw[3]];
    Some(match data {
        ElfData::Little => u32::from_le_bytes(chunk),
        ElfData::Big => u32::from_be_bytes(chunk),
    })
}

fn elf_u64(bytes: &[u8], at: usize, data: ElfData) -> Option<u64> {
    let raw = bytes.get(at..at + 8)?;
    let chunk = [
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ];
    Some(match data {
        ElfData::Little => u64::from_le_bytes(chunk),
        ElfData::Big => u64::from_be_bytes(chunk),
    })
}

fn pe_map(bytes: &[u8], header: &PeHeader, map: &mut Map) {
    let count = usize::from(header.sections).min(REGION_CAP);
    let table = header.section_off as usize;
    map.cover(
        table
            .saturating_add(count.saturating_mul(40))
            .min(bytes.len()),
    );
    let mut at = table;
    for _ in 0..count {
        if at + 40 > bytes.len() {
            break;
        }
        let name = pe_name(&bytes[at..at + 8]);
        let raw = crate::pe::header::u32_at(bytes, at + 16).unwrap_or(0) as usize;
        let ptr = crate::pe::header::u32_at(bytes, at + 20).unwrap_or(0) as usize;
        if raw > 0 && ptr < bytes.len() {
            map.push_section(ptr, ptr.saturating_add(raw).min(bytes.len()), name);
        }
        at += 40;
    }
    if let Some((off, size)) = crate::pe::load::data_dir(bytes, header, 4) {
        let start = off as usize;
        if size > 0 && start < bytes.len() {
            map.mark_signer(start, start.saturating_add(size as usize).min(bytes.len()));
        }
    }
    pe_sea(bytes, header, map);
    map.cover((header.size_of_headers as usize).min(bytes.len()));
}

fn ascii_name(raw: &[u8]) -> Option<String> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let slice = &raw[..end];
    if slice.is_empty() || !slice.iter().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    Some(String::from_utf8_lossy(slice).into_owned())
}

fn pe_name(raw: &[u8]) -> String {
    ascii_name(raw).unwrap_or_else(|| "section".to_string())
}

fn pe_sea(bytes: &[u8], header: &PeHeader, map: &mut Map) {
    let Some((rva, size)) = crate::pe::load::data_dir(bytes, header, 2) else {
        return;
    };
    if size < 16 {
        return;
    }
    let sections = crate::pe::load::sections(bytes, header);
    let Some(base) = crate::pe::load::rva_off(&sections, rva) else {
        return;
    };
    walk_resource(bytes, base, 0, 0, false, &sections, map);
}

fn walk_resource(
    bytes: &[u8],
    base: usize,
    dir: usize,
    depth: usize,
    sea_path: bool,
    sections: &[crate::pe::load::Sec],
    map: &mut Map,
) {
    if depth > 3 {
        return;
    }
    let at = base.saturating_add(dir);
    if at.saturating_add(16) > bytes.len() {
        return;
    }
    let named = crate::pe::header::u16_at(bytes, at + 12).unwrap_or(0) as usize;
    let ids = crate::pe::header::u16_at(bytes, at + 14).unwrap_or(0) as usize;
    let count = named.saturating_add(ids).min(64);
    let mut entry = at + 16;
    for _ in 0..count {
        if entry + 8 > bytes.len() {
            return;
        }
        let name = crate::pe::header::u32_at(bytes, entry).unwrap_or(0);
        let offset = crate::pe::header::u32_at(bytes, entry + 4).unwrap_or(0);
        let mut child_sea = sea_path;
        if name & 0x8000_0000 != 0 {
            let name_at = base.saturating_add((name & 0x7fff_ffff) as usize);
            if resource_name(bytes, name_at).as_deref() == Some("NODE_SEA_BLOB") {
                child_sea = true;
            }
        }
        let next = (offset & 0x7fff_ffff) as usize;
        if offset & 0x8000_0000 != 0 {
            walk_resource(bytes, base, next, depth + 1, child_sea, sections, map);
        } else if child_sea {
            let data = base.saturating_add(next);
            if data + 8 <= bytes.len() {
                let data_rva = crate::pe::header::u32_at(bytes, data).unwrap_or(0);
                let data_size = crate::pe::header::u32_at(bytes, data + 4).unwrap_or(0) as usize;
                if let Some(file_off) = crate::pe::load::rva_off(sections, data_rva) {
                    if data_size > 0 {
                        map.mark_sea(
                            file_off,
                            file_off.saturating_add(data_size).min(bytes.len()),
                        );
                    }
                }
            }
        }
        entry += 8;
    }
}

fn resource_name(bytes: &[u8], at: usize) -> Option<String> {
    let count = crate::pe::header::u16_at(bytes, at)? as usize;
    if count == 0 || count > 64 {
        return None;
    }
    let mut name = String::new();
    for index in 0..count {
        let unit = crate::pe::header::u16_at(bytes, at + 2 + index * 2)?;
        if unit > 0x7f {
            return None;
        }
        name.push(unit as u8 as char);
    }
    Some(name)
}

fn macho_map(bytes: &[u8], image: &Image, map: &mut Map) {
    match image {
        Image::Thin(_) => macho_slice(bytes, 0, map),
        Image::Fat(fat) => {
            for arch in &fat.arches {
                let Some(base) = usize::try_from(arch.offset).ok() else {
                    continue;
                };
                if base < bytes.len() {
                    macho_slice(bytes, base, map);
                }
            }
        }
    }
}

fn macho_slice(bytes: &[u8], base: usize, map: &mut Map) {
    let Some(slice) = bytes.get(base..) else {
        return;
    };
    let Ok(Image::Thin(thin)) = crate::macho::header::parse(slice) else {
        return;
    };
    let header = thin.class.header_bytes() as usize;
    let data = thin.data;
    let commands = header.saturating_add(thin.sizeofcmds as usize);
    map.cover(base.saturating_add(commands).min(bytes.len()));
    let mut at = base + header;
    let end = base.saturating_add(commands).min(bytes.len());
    for _ in 0..thin.ncmds.min(REGION_CAP as u32) {
        if at + 8 > end {
            break;
        }
        let cmd = crate::macho::header::u32_at(bytes, at, data).unwrap_or(0);
        let cmdsize = crate::macho::header::u32_at(bytes, at + 4, data).unwrap_or(0) as usize;
        if cmdsize < 8 || at.saturating_add(cmdsize) > bytes.len() {
            break;
        }
        if cmd == 0x19 && thin.class == MachClass::Mach64 {
            macho_segment(bytes, at, cmdsize, base, data, true, map);
        } else if cmd == 0x1 && thin.class == MachClass::Mach32 {
            macho_segment(bytes, at, cmdsize, base, data, false, map);
        } else if cmd == 0x1d {
            let off = crate::macho::header::u32_at(bytes, at + 8, data).unwrap_or(0) as usize;
            let size = crate::macho::header::u32_at(bytes, at + 12, data).unwrap_or(0) as usize;
            let start = base.saturating_add(off);
            if size > 0 && start < bytes.len() {
                map.mark_signer(start, start.saturating_add(size).min(bytes.len()));
            }
        }
        at += cmdsize;
    }
}

fn macho_segment(
    bytes: &[u8],
    at: usize,
    cmdsize: usize,
    base: usize,
    data: MachData,
    wide: bool,
    map: &mut Map,
) {
    let head = if wide { 72 } else { 56 };
    if cmdsize < head || at + head > bytes.len() {
        return;
    }
    let name = ascii_name(&bytes[at + 8..at + 24]);
    let (fileoff, filesize, nsects) = if wide {
        (
            crate::macho::header::u64_at(bytes, at + 40, data).unwrap_or(0),
            crate::macho::header::u64_at(bytes, at + 48, data).unwrap_or(0),
            crate::macho::header::u32_at(bytes, at + 64, data).unwrap_or(0),
        )
    } else {
        (
            u64::from(crate::macho::header::u32_at(bytes, at + 32, data).unwrap_or(0)),
            u64::from(crate::macho::header::u32_at(bytes, at + 36, data).unwrap_or(0)),
            crate::macho::header::u32_at(bytes, at + 48, data).unwrap_or(0),
        )
    };
    let abs = (base as u64).saturating_add(fileoff);
    if let Some((start, end)) = clamp(abs, filesize, bytes.len()) {
        map.push_segment(start, end, name.unwrap_or_else(|| "segment".to_string()));
    }
    let sect_size = if wide { 80 } else { 68 };
    let mut sect = at + head;
    for _ in 0..nsects.min(64) {
        if sect + sect_size > at + cmdsize || sect + sect_size > bytes.len() {
            break;
        }
        let sect_name = ascii_name(&bytes[sect..sect + 16]);
        let (offset, size, flags) = if wide {
            (
                u64::from(crate::macho::header::u32_at(bytes, sect + 48, data).unwrap_or(0)),
                crate::macho::header::u64_at(bytes, sect + 40, data).unwrap_or(0),
                crate::macho::header::u32_at(bytes, sect + 64, data).unwrap_or(0),
            )
        } else {
            (
                u64::from(crate::macho::header::u32_at(bytes, sect + 40, data).unwrap_or(0)),
                u64::from(crate::macho::header::u32_at(bytes, sect + 36, data).unwrap_or(0)),
                crate::macho::header::u32_at(bytes, sect + 56, data).unwrap_or(0),
            )
        };
        if flags & 1 == 0 {
            let abs = (base as u64).saturating_add(offset);
            if let Some((start, end)) = clamp(abs, size, bytes.len()) {
                map.push_section(
                    start,
                    end,
                    sect_name.unwrap_or_else(|| "section".to_string()),
                );
            }
        }
        sect += sect_size;
    }
}
