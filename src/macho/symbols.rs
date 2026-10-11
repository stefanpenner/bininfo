/*
---
why: This file reads Mach-O symbol records.
uses: bininfo
how: bininfo calls this file to count imports and exports.
This file does not print the page.
---
*/

//! Mach-O build version, dylib versions, and loader symbol records.
//! This module does not print.

use super::header::{self, Class, Data, Image, Thin};
use super::load::{Commands, Slice};
use super::words::{self, cpu_name};
use crate::claim::{CpuFloor, Version};

const SYM_CAP: u32 = 16384;
const NODE_CAP: u32 = 10000;
const NAME_CAP: usize = 4096;

/// compatibility_version and current_version for one linked dylib.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dylib {
    pub name: String,
    pub compat: String,
    pub current: String,
}

/// LC_BUILD_VERSION, or LC_VERSION_MIN_MACOSX when that is the only record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Build {
    pub platform: u32,
    pub minos: Version,
    pub sdk: Version,
    pub source: &'static str,
}

/// One chained-fixup import. `ordinal` is the dylib ordinal in that record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedImport {
    pub ordinal: u32,
    pub name: String,
    pub weak: bool,
}

/// One bind opcode import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindImport {
    pub ordinal: u32,
    pub name: String,
}

/// Records that sit beside `load`. Absent commands stay `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extra {
    pub build: Option<Build>,
    pub dylibs: Vec<Dylib>,
    pub chained: Option<u32>,
    pub chained_rows: Vec<ChainedImport>,
    pub bind: Option<u32>,
    pub bind_rows: Vec<BindImport>,
    pub exports: u32,
    pub export_names: Vec<String>,
    pub export_cmd: &'static str,
    pub symtab: bool,
    pub entry_name: Option<String>,
    pub entry_note: &'static str,
    pub rows: bool,
}

impl Extra {
    pub fn empty() -> Self {
        Self {
            build: None,
            dylibs: Vec::new(),
            chained: None,
            chained_rows: Vec::new(),
            bind: None,
            bind_rows: Vec::new(),
            exports: 0,
            export_names: Vec::new(),
            export_cmd: "LC_DYLD_EXPORTS_TRIE",
            symtab: false,
            entry_name: None,
            entry_note: "[LC_SYMTAB] No symbol value equals the entry.",
            rows: false,
        }
    }
}

pub fn dotted(version: Version) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}

pub fn packed(value: u32) -> Version {
    Version {
        major: value >> 16,
        minor: (value >> 8) & 0xff,
        patch: value & 0xff,
    }
}

pub fn dylib_versions(bytes: &[u8], at: usize, size: u32, data: Data) -> (String, String) {
    if size < 24 {
        return ("0.0.0".into(), "0.0.0".into());
    }
    let current = header::u32_at(bytes, at + 16, data).unwrap_or(0);
    let compat = header::u32_at(bytes, at + 20, data).unwrap_or(0);
    (dotted(packed(compat)), dotted(packed(current)))
}

pub fn build_version(bytes: &[u8], at: usize, size: u32, data: Data) -> Option<Build> {
    if size < 24 {
        return None;
    }
    Some(Build {
        platform: header::u32_at(bytes, at + 8, data)?,
        minos: packed(header::u32_at(bytes, at + 12, data)?),
        sdk: packed(header::u32_at(bytes, at + 16, data)?),
        source: "LC_BUILD_VERSION",
    })
}

pub fn version_min(bytes: &[u8], at: usize, size: u32, data: Data) -> Option<Build> {
    if size < 16 {
        return None;
    }
    Some(Build {
        platform: 1,
        minos: packed(header::u32_at(bytes, at + 8, data)?),
        sdk: packed(header::u32_at(bytes, at + 12, data)?),
        source: "LC_VERSION_MIN_MACOSX",
    })
}

/// Import count from LC_DYLD_CHAINED_FIXUPS. The count cannot pass the data blob.
pub fn chained(
    bytes: &[u8],
    dataoff: u32,
    datasize: u32,
    data: Data,
    rows: bool,
) -> (u32, Vec<ChainedImport>) {
    let Some(start) = usize::try_from(dataoff).ok() else {
        return (0, Vec::new());
    };
    let size = datasize as usize;
    if start.checked_add(24).is_none_or(|end| end > bytes.len()) || size < 24 {
        return (0, Vec::new());
    }
    let end = start.saturating_add(size).min(bytes.len());
    let imports_off = header::u32_at(bytes, start + 8, data).unwrap_or(0);
    let symbols_off = header::u32_at(bytes, start + 12, data).unwrap_or(0);
    let imports_count = header::u32_at(bytes, start + 16, data).unwrap_or(0);
    let format = header::u32_at(bytes, start + 20, data).unwrap_or(0);
    let stride = match format {
        2 => 8usize,
        3 => 16,
        _ => 4,
    };
    let room = (end.saturating_sub(start)).saturating_sub(imports_off as usize) / stride.max(1);
    let count = imports_count.min(room as u32).min(SYM_CAP);
    let mut found = Vec::new();
    if rows && matches!(format, 1 | 2 | 3) {
        for index in 0..count {
            let Some(at) = start
                .checked_add(imports_off as usize)
                .and_then(|base| base.checked_add(index as usize * stride))
            else {
                break;
            };
            let (ordinal, name_off, weak) = if format == 3 {
                let Some(wide) = header::u64_at(bytes, at, data) else {
                    break;
                };
                (
                    (wide & 0xffff) as u32,
                    (wide >> 32) as u32,
                    (wide >> 16) & 1 == 1,
                )
            } else {
                let Some(word) = header::u32_at(bytes, at, data) else {
                    break;
                };
                (word & 0xff, word >> 9, (word >> 8) & 1 == 1)
            };
            let name = cstring(
                bytes,
                start
                    .saturating_add(symbols_off as usize)
                    .saturating_add(name_off as usize),
                end,
            );
            found.push(ChainedImport {
                ordinal,
                name,
                weak,
            });
        }
    }
    (count, found)
}

pub fn bind(bytes: &[u8], off: u32, size: u32, _data: Data, rows: bool) -> (u32, Vec<BindImport>) {
    let Some(start) = usize::try_from(off).ok() else {
        return (0, Vec::new());
    };
    if size == 0 || start >= bytes.len() {
        return (0, Vec::new());
    }
    let end = start.saturating_add(size as usize).min(bytes.len());
    let mut at = start;
    let mut count = 0u32;
    let mut ordinal = 0u32;
    let mut name = String::new();
    let mut found = Vec::new();
    while at < end && count < SYM_CAP {
        let byte = bytes[at];
        at += 1;
        let op = byte & 0xf0;
        let imm = u32::from(byte & 0x0f);
        match op {
            0x00 => break,
            0x10 => ordinal = imm,
            0x20 => {
                let Some((value, next)) = uleb(bytes, at, end) else {
                    break;
                };
                ordinal = value.min(u64::from(u32::MAX)) as u32;
                at = next;
            }
            0x30 => ordinal = imm,
            0x40 => {
                let (text, next) = cstring_span(bytes, at, end);
                name = text;
                at = next;
            }
            0x50 => {}
            0x60 | 0x70 | 0x80 => {
                let Some((_, next)) = uleb(bytes, at, end) else {
                    break;
                };
                at = next;
            }
            0x90 | 0xb0 => push_bind(&mut count, &mut found, rows, ordinal, &name),
            0xa0 => {
                push_bind(&mut count, &mut found, rows, ordinal, &name);
                let Some((_, next)) = uleb(bytes, at, end) else {
                    break;
                };
                at = next;
            }
            0xc0 => {
                let Some((times, next)) = uleb(bytes, at, end) else {
                    break;
                };
                let Some((_, next)) = uleb(bytes, next, end) else {
                    break;
                };
                at = next;
                let room = SYM_CAP - count;
                let add = u32::try_from(times).unwrap_or(u32::MAX).min(room);
                if rows {
                    for _ in 0..add.min(64) {
                        found.push(BindImport {
                            ordinal,
                            name: name.clone(),
                        });
                    }
                }
                count = count.saturating_add(add);
            }
            _ => break,
        }
    }
    (count, found)
}

fn push_bind(count: &mut u32, found: &mut Vec<BindImport>, rows: bool, ordinal: u32, name: &str) {
    if *count >= SYM_CAP {
        return;
    }
    if rows && found.len() < 64 {
        found.push(BindImport {
            ordinal,
            name: name.to_string(),
        });
    }
    *count = count.saturating_add(1);
}

/// Terminal count of an export trie. The walk is capped.
pub fn exports(bytes: &[u8], off: u32, size: u32, rows: bool) -> (u32, Vec<String>) {
    let Some(start) = usize::try_from(off).ok() else {
        return (0, Vec::new());
    };
    if size == 0 || start >= bytes.len() {
        return (0, Vec::new());
    }
    let end = start.saturating_add(size as usize).min(bytes.len());
    let mut count = 0u32;
    let mut names = Vec::new();
    let mut stack = vec![(start, String::new(), 0u32)];
    let mut seen = 0u32;
    let mut visited = Vec::new();
    while let Some((node, prefix, depth)) = stack.pop() {
        if seen >= NODE_CAP || depth > 32 || node >= end || visited.contains(&node) {
            continue;
        }
        visited.push(node);
        seen += 1;
        let Some((terminal, mut at)) = uleb(bytes, node, end) else {
            continue;
        };
        if terminal > 0 {
            count = count.saturating_add(1).min(SYM_CAP);
            if rows && names.len() < 64 {
                names.push(prefix.clone());
            }
            let skip = (terminal as usize).min(end.saturating_sub(at));
            at = at.saturating_add(skip);
            if terminal as usize > skip {
                continue;
            }
        }
        let Some((children, mut at)) = uleb(bytes, at, end) else {
            continue;
        };
        for _ in 0..children.min(64) {
            if at >= end {
                break;
            }
            let (edge, next) = cstring_span(bytes, at, end);
            let Some((child, next)) = uleb(bytes, next, end) else {
                break;
            };
            at = next;
            let child_at = start.saturating_add(child as usize);
            if child_at >= end || child_at == node {
                continue;
            }
            if prefix.len() + edge.len() > NAME_CAP {
                continue;
            }
            let mut name = prefix.clone();
            name.push_str(&edge);
            stack.push((child_at, name, depth + 1));
        }
    }
    (count, names)
}

pub fn nlist_entry(
    bytes: &[u8],
    thin: &Thin,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    entry: u64,
) -> Option<String> {
    if nsyms == 0 || symoff == 0 {
        return None;
    }
    let step = match thin.class {
        Class::Mach32 => 12usize,
        _ => 16,
    };
    let start = symoff as usize;
    let n = nsyms.min(SYM_CAP);
    for index in 0..n {
        let at = start.checked_add(index as usize * step)?;
        if at.checked_add(step)? > bytes.len() {
            break;
        }
        let strx = header::u32_at(bytes, at, thin.data)?;
        let value = if step == 12 {
            header::u32_at(bytes, at + 8, thin.data)? as u64
        } else {
            header::u64_at(bytes, at + 8, thin.data)?
        };
        if value != entry {
            continue;
        }
        let table = stroff as usize;
        let end = table.saturating_add(strsize as usize).min(bytes.len());
        let name = cstring(bytes, table.saturating_add(strx as usize), end);
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

pub fn floors(image: &Image, commands: &Commands, slices: &[Slice]) -> Vec<CpuFloor> {
    match image {
        Image::Thin(thin) => vec![one_floor(thin.cputype, thin.cpusubtype, &commands.extra)],
        Image::Fat(_) => slices
            .iter()
            .filter(|slice| slice.thin.is_some())
            .map(|slice| one_floor(slice.cputype, slice.cpusubtype, &slice.commands.extra))
            .filter(|floor| !floor.word.is_empty() || floor.minos.is_some())
            .collect(),
    }
}

fn one_floor(cputype: u32, subtype: u32, extra: &Extra) -> CpuFloor {
    let family = extra
        .build
        .map(|build| words::platform_family(build.platform))
        .unwrap_or("");
    CpuFloor {
        word: cpu_name(cputype).unwrap_or(""),
        arm64e: words::is_arm64e(cputype, subtype),
        minos: extra.build.map(|build| build.minos),
        os_family: family,
    }
}

fn uleb(bytes: &[u8], at: usize, end: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut cursor = at;
    for _ in 0..10 {
        if cursor >= end || cursor >= bytes.len() {
            return None;
        }
        let byte = bytes[cursor];
        cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, cursor));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

fn cstring(bytes: &[u8], at: usize, end: usize) -> String {
    cstring_span(bytes, at, end).0
}

fn cstring_span(bytes: &[u8], at: usize, end: usize) -> (String, usize) {
    if at >= end || at >= bytes.len() {
        return (String::new(), at);
    }
    let stop = end.min(bytes.len()).min(at.saturating_add(NAME_CAP));
    let slice = &bytes[at..stop];
    let n = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    let next = at + n + usize::from(n < slice.len());
    (
        String::from_utf8_lossy(&slice[..n]).into_owned(),
        next.min(end),
    )
}

#[cfg(test)]
mod tests {
    use super::super::header::Data;
    use super::*;

    fn put_u32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], at: usize, v: u64) {
        buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn chained_format3_uses_wide_ordinal_and_name() {
        let mut bytes = vec![0u8; 64];
        put_u32(&mut bytes, 8, 32);
        put_u32(&mut bytes, 12, 48);
        put_u32(&mut bytes, 16, 1);
        put_u32(&mut bytes, 20, 3);
        put_u64(&mut bytes, 32, 256 | (4u64 << 32));
        bytes[48..51].copy_from_slice(b"no\0");
        bytes[52..55].copy_from_slice(b"ok\0");
        let (count, rows) = chained(&bytes, 0, bytes.len() as u32, Data::Little, true);
        assert_eq!(count, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ordinal, 256);
        assert_eq!(rows[0].name, "ok");
    }

    #[test]
    fn export_trie_cycle_counts_each_node_once() {
        let bytes = [
            0x01, 0x00, 0x01, b'a', 0x00, 0x06, 0x01, 0x00, 0x01, b'b', 0x00, 0x00,
        ];
        let (count, _) = exports(&bytes, 0, bytes.len() as u32, false);
        assert_eq!(count, 2);
    }

    #[test]
    fn bind_repeat_count_saturates_at_sym_cap() {
        let bytes = [0xc0, 0x80, 0x80, 0x80, 0x80, 0x10, 0x00];
        let (count, rows) = bind(&bytes, 0, bytes.len() as u32, Data::Little, false);
        assert_eq!(count, 16384);
        assert!(rows.is_empty());
    }
}
