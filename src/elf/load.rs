/*
---
why: This file reads how an ELF file starts.
uses: bininfo
how: bininfo calls this file to read program headers.
This file reads DT_SONAME, filter, auxiliary, and loader flags.
This file does not print the page.
---
*/

//! How an ELF file starts, and which files it must open.
//! This module reads program headers. It does not print them.

use super::header::{Class, Data, Header, Type};
pub(crate) use crate::kind::name as kind_name;
pub use crate::kind::Kind;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_SYMBOLIC: u64 = 16;
const DT_TEXTREL: u64 = 22;
const DT_BIND_NOW: u64 = 24;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DT_AUXILIARY: u64 = 0x7fff_fffd;
const DT_FILTER: u64 = 0x7fff_ffff;
const DF_ORIGIN: u64 = 0x1;
const DF_SYMBOLIC: u64 = 0x2;
const DF_TEXTREL: u64 = 0x4;
const DF_BIND_NOW: u64 = 0x8;
const DF_STATIC_TLS: u64 = 0x10;
const DF_1_PIE: u64 = 0x0800_0000;
const NAME_CAP: usize = 4096;
const IMPORT_CAP: usize = 256;

/// Facts from the program headers and from `PT_DYNAMIC`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Load {
    pub kind: Kind,             // static, dynamic-pie, static-pie, or shared.
    pub interp: Option<String>, // Path of the loader. None means this file starts itself.
    pub soname: Option<String>, // DT_SONAME. None means the file has no soname.
    pub needed: Vec<String>,    // Library names the loader opens.
    pub filter: Vec<String>,    // DT_FILTER names, in file order.
    pub auxiliary: Vec<String>, // DT_AUXILIARY names, in file order.
    pub runpath: Vec<String>,   // DT_RUNPATH directories. A colon splits one string.
    pub rpath: Vec<String>,     // DT_RPATH directories. A colon splits one string.
    pub flags: Vec<String>,     // DT_FLAGS and DT_FLAGS_1 words, in flag order.
    pub delay: Vec<String>,     // Always empty. ELF has no delay-import record.
    pub pie: bool,              // PIE bit in DT_FLAGS_1.
}

pub fn read(bytes: &[u8], header: &Header) -> Load {
    let rows = program_headers(bytes, header);
    let interp = rows.iter().find_map(|row| interp_path(bytes, row));
    let dyns = rows
        .iter()
        .find(|row| row.ty == PT_DYNAMIC)
        .map(|row| dynamic_facts(bytes, header, &rows, row))
        .unwrap_or_else(DynFacts::empty);
    Load {
        kind: classify(header.kind, interp.is_some(), dyns.pie),
        interp,
        soname: dyns.soname,
        needed: dyns.needed,
        filter: dyns.filter,
        auxiliary: dyns.auxiliary,
        runpath: dyns.runpath,
        rpath: dyns.rpath,
        flags: dyns.flags,
        delay: Vec::new(),
        pie: dyns.pie,
    }
}

pub(crate) fn kind_note(kind: Kind) -> &'static str {
    match kind {
        Kind::Static => "EXEC and no loader.",
        Kind::Dynamic => "A loader is present and the PIE bit is clear.",
        Kind::DynamicPie => "A loader is present and the PIE bit is set.",
        Kind::StaticPie => "DYN, no loader, and the PIE bit is set.",
        Kind::Shared => "DYN, no loader, and the PIE bit is clear.",
        Kind::Rel => "REL. The kernel does not run this file.",
        Kind::Other => "This e_type is outside the four start kinds.",
    }
}

fn classify(ty: Type, interp: bool, pie: bool) -> Kind {
    match ty {
        Type::Rel => Kind::Rel,
        Type::Exec if !interp => Kind::Static,
        Type::Exec | Type::Dyn if interp && pie => Kind::DynamicPie,
        Type::Exec | Type::Dyn if interp => Kind::Dynamic,
        Type::Dyn if pie => Kind::StaticPie,
        Type::Dyn => Kind::Shared,
        _ => Kind::Other,
    }
}

pub(crate) struct Phdr {
    pub(crate) ty: u32,
    pub(crate) offset: u64,
    pub(crate) vaddr: u64,
    pub(crate) filesz: u64,
    pub(crate) align: u64,
}

pub(crate) fn program_headers(bytes: &[u8], header: &Header) -> Vec<Phdr> {
    let need = match header.class {
        Class::Elf32 => 32,
        Class::Elf64 => 56,
    };
    if header.phnum == 0 || (header.phentsize as usize) < need {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for index in 0..header.phnum {
        let Some(at) = row_start(header, index) else {
            break;
        };
        if at.checked_add(need).is_none_or(|end| end > bytes.len()) {
            break;
        }
        rows.push(decode_phdr(bytes, at, header));
    }
    rows
}

fn row_start(header: &Header, index: u16) -> Option<usize> {
    let step = header.phentsize as u64;
    let at = header.phoff.checked_add(step.checked_mul(index as u64)?)?;
    usize::try_from(at).ok()
}

fn decode_phdr(bytes: &[u8], at: usize, header: &Header) -> Phdr {
    match header.class {
        Class::Elf64 => Phdr {
            ty: u32_at(bytes, at, header.data),
            offset: u64_at(bytes, at + 8, header.data),
            vaddr: u64_at(bytes, at + 16, header.data),
            filesz: u64_at(bytes, at + 32, header.data),
            align: u64_at(bytes, at + 48, header.data),
        },
        Class::Elf32 => Phdr {
            ty: u32_at(bytes, at, header.data),
            offset: u32_at(bytes, at + 4, header.data) as u64,
            vaddr: u32_at(bytes, at + 8, header.data) as u64,
            filesz: u32_at(bytes, at + 16, header.data) as u64,
            align: u32_at(bytes, at + 28, header.data) as u64,
        },
    }
}

fn interp_path(bytes: &[u8], row: &Phdr) -> Option<String> {
    if row.ty != PT_INTERP {
        return None;
    }
    Some(read_text(bytes, row.offset, row.filesz))
}

struct DynFacts {
    pie: bool,
    soname: Option<String>,
    needed: Vec<String>,
    filter: Vec<String>,
    auxiliary: Vec<String>,
    runpath: Vec<String>,
    rpath: Vec<String>,
    flags: Vec<String>,
}

impl DynFacts {
    fn empty() -> Self {
        Self {
            pie: false,
            soname: None,
            needed: Vec::new(),
            filter: Vec::new(),
            auxiliary: Vec::new(),
            runpath: Vec::new(),
            rpath: Vec::new(),
            flags: Vec::new(),
        }
    }
}

fn dynamic_facts(bytes: &[u8], header: &Header, rows: &[Phdr], row: &Phdr) -> DynFacts {
    let mut strtab = None;
    let mut flags = 0u64;
    let mut flags1 = 0u64;
    let mut symbolic = false;
    let mut textrel = false;
    let mut bind_now = false;
    let mut soname_at = None;
    let mut needed_at = Vec::new();
    let mut filter_at = Vec::new();
    let mut auxiliary_at = Vec::new();
    let mut runpath_at = Vec::new();
    let mut rpath_at = Vec::new();
    for (tag, val) in dyn_pairs(bytes, header, row) {
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab = Some(val),
            DT_FLAGS => flags |= val,
            DT_FLAGS_1 => flags1 |= val,
            DT_NEEDED => needed_at.push(val),
            DT_SONAME if soname_at.is_none() => soname_at = Some(val),
            DT_FILTER => filter_at.push(val),
            DT_AUXILIARY => auxiliary_at.push(val),
            DT_RUNPATH => runpath_at.push(val),
            DT_RPATH => rpath_at.push(val),
            DT_SYMBOLIC => symbolic = true,
            DT_TEXTREL => textrel = true,
            DT_BIND_NOW => bind_now = true,
            _ => {}
        }
    }
    let words = flag_words(flags, flags1, symbolic, textrel, bind_now);
    let pie = flags1 & DF_1_PIE != 0;
    let Some(base) = strtab.and_then(|vaddr| vaddr_to_offset(rows, vaddr)) else {
        let mut empty = DynFacts::empty();
        empty.pie = pie;
        empty.flags = words;
        return empty;
    };
    let soname = soname_at
        .and_then(|off| base.checked_add(off))
        .map(|at| read_text(bytes, at, NAME_CAP as u64))
        .filter(|name| !name.is_empty());
    DynFacts {
        pie,
        soname,
        needed: names_at(bytes, base, &needed_at),
        filter: names_at(bytes, base, &filter_at),
        auxiliary: names_at(bytes, base, &auxiliary_at),
        runpath: split_dirs(names_at(bytes, base, &runpath_at)),
        rpath: split_dirs(names_at(bytes, base, &rpath_at)),
        flags: words,
    }
}

fn flag_words(
    flags: u64,
    flags1: u64,
    symbolic: bool,
    textrel: bool,
    bind_now: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if flags & DF_ORIGIN != 0 || flags1 & 0x80 != 0 {
        out.push("origin".into());
    }
    if symbolic || flags & DF_SYMBOLIC != 0 {
        out.push("symbolic".into());
    }
    if textrel || flags & DF_TEXTREL != 0 {
        out.push("textrel".into());
    }
    if bind_now || flags & DF_BIND_NOW != 0 {
        out.push("bind-now".into());
    }
    if flags & DF_STATIC_TLS != 0 {
        out.push("static-tls".into());
    }
    const FLAGS1: &[(u64, &str)] = &[
        (0x1, "now"),
        (0x2, "global"),
        (0x4, "group"),
        (0x8, "nodelete"),
        (0x10, "loadfltr"),
        (0x20, "initfirst"),
        (0x40, "noopen"),
        (0x100, "direct"),
        (0x200, "trans"),
        (0x400, "interpose"),
        (0x800, "nodeflib"),
        (0x1000, "nodump"),
        (0x2000, "confalt"),
        (0x4000, "endfiltee"),
        (0x8000, "dispreldne"),
        (0x1_0000, "disprelpnd"),
        (0x2_0000, "nodirect"),
        (0x4_0000, "ignmuldef"),
        (0x8_0000, "noksyms"),
        (0x10_0000, "nohdr"),
        (0x20_0000, "edited"),
        (0x40_0000, "noreloc"),
        (0x80_0000, "symintpose"),
        (0x100_0000, "globaudit"),
        (0x200_0000, "singleton"),
        (0x400_0000, "stub"),
        (0x800_0000, "pie"),
        (0x1000_0000, "kmod"),
        (0x2000_0000, "weakfilter"),
        (0x4000_0000, "nocommon"),
    ];
    for (bit, word) in FLAGS1 {
        if flags1 & bit != 0 {
            out.push((*word).into());
        }
    }
    push_unknown(&mut out, flags, 0x1f);
    let known1 = FLAGS1.iter().fold(0x80u64, |mask, (bit, _)| mask | bit);
    push_unknown(&mut out, flags1, known1);
    out
}

fn push_unknown(out: &mut Vec<String>, value: u64, known: u64) {
    let mut rest = value & !known;
    let mut bit = 1u64;
    while rest != 0 {
        if rest & bit != 0 {
            out.push(format!("0x{bit:x}"));
            rest &= !bit;
        }
        if bit == 1 << 63 {
            break;
        }
        bit <<= 1;
    }
}

fn names_at(bytes: &[u8], base: u64, offs: &[u64]) -> Vec<String> {
    offs.iter()
        .take(IMPORT_CAP)
        .filter_map(|off| base.checked_add(*off))
        .map(|at| read_text(bytes, at, NAME_CAP as u64))
        .filter(|name| !name.is_empty())
        .collect()
}

fn split_dirs(raws: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for raw in raws {
        for part in raw.split(':') {
            if part.is_empty() {
                continue;
            }
            if out.len() == IMPORT_CAP {
                return out;
            }
            out.push(part.to_string());
        }
    }
    out
}

pub(crate) fn dyn_pairs(bytes: &[u8], header: &Header, row: &Phdr) -> Vec<(u64, u64)> {
    let step = match header.class {
        Class::Elf32 => 8,
        Class::Elf64 => 16,
    };
    let Some(start) = usize::try_from(row.offset).ok() else {
        return Vec::new();
    };
    if start >= bytes.len() {
        return Vec::new();
    }
    let avail = bytes.len() - start;
    let span = usize::try_from(row.filesz).unwrap_or(usize::MAX).min(avail);
    let mut pairs = Vec::new();
    let mut at = start;
    while at + step <= start + span {
        let (tag, val) = match header.class {
            Class::Elf64 => (
                u64_at(bytes, at, header.data),
                u64_at(bytes, at + 8, header.data),
            ),
            Class::Elf32 => (
                u32_at(bytes, at, header.data) as u64,
                u32_at(bytes, at + 4, header.data) as u64,
            ),
        };
        pairs.push((tag, val));
        if tag == DT_NULL {
            break;
        }
        at += step;
    }
    pairs
}

pub(crate) fn vaddr_to_offset(rows: &[Phdr], vaddr: u64) -> Option<u64> {
    rows.iter().find_map(|row| {
        if row.ty != PT_LOAD || vaddr < row.vaddr {
            return None;
        }
        let delta = vaddr - row.vaddr;
        if delta < row.filesz {
            row.offset.checked_add(delta)
        } else {
            None
        }
    })
}

pub(crate) fn read_text(bytes: &[u8], offset: u64, limit: u64) -> String {
    let Ok(start) = usize::try_from(offset) else {
        return String::new();
    };
    if start >= bytes.len() {
        return String::new();
    }
    let room = (bytes.len() - start) as u64;
    let take = usize::try_from(limit.min(room).min(NAME_CAP as u64)).unwrap_or(0);
    let slice = &bytes[start..start + take];
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn u32_at(bytes: &[u8], at: usize, data: Data) -> u32 {
    let b = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
    match data {
        Data::Little => u32::from_le_bytes(b),
        Data::Big => u32::from_be_bytes(b),
    }
}

fn u64_at(bytes: &[u8], at: usize, data: Data) -> u64 {
    let b = [
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ];
    match data {
        Data::Little => u64::from_le_bytes(b),
        Data::Big => u64::from_be_bytes(b),
    }
}

#[cfg(test)]
mod tests {
    use super::super::header::{self, Data, Type};
    use super::*;

    fn classify_of(ty: Type, interp: bool, pie: bool) -> Kind {
        classify(ty, interp, pie)
    }

    #[test]
    fn the_four_start_kinds() {
        assert_eq!(classify_of(Type::Exec, false, false), Kind::Static);
        assert_eq!(classify_of(Type::Dyn, true, true), Kind::DynamicPie);
        assert_eq!(classify_of(Type::Dyn, false, true), Kind::StaticPie);
        assert_eq!(classify_of(Type::Dyn, false, false), Kind::Shared);
        assert_eq!(classify_of(Type::Exec, true, false), Kind::Dynamic);
        assert_eq!(classify_of(Type::Rel, false, false), Kind::Rel);
    }

    #[test]
    fn static_exec_names_no_library() {
        let bytes = elf_header(Type::Exec, 0, 0);
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert_eq!(load.kind, Kind::Static);
        assert_eq!(load.interp, None);
        assert!(load.needed.is_empty());
        assert!(load.soname.is_none());
        assert!(load.filter.is_empty());
        assert!(load.auxiliary.is_empty());
        assert!(load.flags.is_empty());
        assert!(load.runpath.is_empty());
        assert!(load.rpath.is_empty());
        assert!(!load.pie);
    }

    #[test]
    fn soname_filter_auxiliary_and_flag_words_keep_tag_order() {
        let bytes = elf_with_dynamic_endian(
            Data::Little,
            Type::Dyn,
            DF_1_PIE | 0x1 | 0x20_0000 | (1 << 31),
            None,
            &[],
            None,
            None,
            Extra {
                soname: Some("libfoo.so.1"),
                filter: &["libbar.so"],
                auxiliary: &["libaux.so"],
                flags: DF_ORIGIN,
                symbolic: true,
                textrel: false,
                bind_now: true,
            },
        );
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert_eq!(load.soname.as_deref(), Some("libfoo.so.1"));
        assert_eq!(load.filter, ["libbar.so"]);
        assert_eq!(load.auxiliary, ["libaux.so"]);
        assert_eq!(
            load.flags,
            [
                "origin",
                "symbolic",
                "bind-now",
                "now",
                "edited",
                "pie",
                "0x80000000"
            ]
        );
        assert!(load.pie);
    }

    #[test]
    fn static_pie_sets_the_pie_bit_and_names_no_loader() {
        let bytes = elf_with_dynamic(Type::Dyn, DF_1_PIE, None, &[]);
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert_eq!(load.kind, Kind::StaticPie);
        assert_eq!(load.interp, None);
        assert!(load.needed.is_empty());
        assert!(load.pie);
    }

    #[test]
    fn dynamic_pie_names_the_loader_and_one_library() {
        let bytes = elf_with_dynamic(
            Type::Dyn,
            DF_1_PIE,
            Some("/lib/ld.so"),
            &["libc.so.6", "libm.so.6"],
        );
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert_eq!(load.kind, Kind::DynamicPie);
        assert_eq!(load.interp.as_deref(), Some("/lib/ld.so"));
        assert_eq!(
            load.needed,
            vec!["libc.so.6".to_string(), "libm.so.6".to_string()]
        );
        assert!(load.pie);
    }

    #[test]
    fn search_paths_keep_tag_order_and_split_on_colon() {
        let bytes = elf_with_dynamic_endian(
            Data::Little,
            Type::Dyn,
            0,
            Some("/lib/ld.so"),
            &["libc.so.6"],
            Some("$ORIGIN/../lib:/opt/lib"),
            Some("/old"),
            Extra::none(),
        );
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert_eq!(load.needed, ["libc.so.6"]);
        assert_eq!(load.runpath, ["$ORIGIN/../lib", "/opt/lib"]);
        assert_eq!(load.rpath, ["/old"]);
    }

    #[test]
    fn shared_library_has_no_pie_bit() {
        let bytes = elf_with_dynamic(Type::Dyn, 0, None, &[]);
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert_eq!(load.kind, Kind::Shared);
        assert!(!load.pie);
    }

    #[test]
    fn big_endian_dynamic_keeps_the_pie_bit() {
        let bytes = elf_with_dynamic_endian(
            Data::Big,
            Type::Dyn,
            DF_1_PIE,
            None,
            &[],
            None,
            None,
            Extra::none(),
        );
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert_eq!(header.data, Data::Big);
        assert_eq!(load.kind, Kind::StaticPie);
        assert!(load.pie);
    }

    #[test]
    fn needed_list_is_capped() {
        let names: Vec<String> = (0..300).map(|index| format!("l{index}.so")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let bytes = elf_with_dynamic(Type::Dyn, 0, None, &refs);
        let header = header::parse(&bytes).unwrap();
        let load = read(&bytes, &header);
        assert!(load.needed.len() <= 256, "{}", load.needed.len());
        assert_eq!(load.needed.len(), 256);
    }

    #[test]
    fn hostile_program_headers_do_not_panic() {
        let mut samples = vec![
            vec![],
            vec![0u8; 64],
            elf_header(Type::Dyn, u64::MAX - 8, 65535),
        ];
        let mut huge = elf_header(Type::Exec, 64, 1);
        huge[54..56].copy_from_slice(&56u16.to_le_bytes());
        huge.truncate(70);
        samples.push(huge);
        for bytes in samples {
            let parsed = std::panic::catch_unwind(|| {
                if let Ok(header) = header::parse(&bytes) {
                    read(&bytes, &header);
                }
            });
            assert!(parsed.is_ok(), "load read panicked");
        }
    }

    fn elf_header(ty: Type, phoff: u64, phnum: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, type_byte(ty), Data::Little);
        put_u16(&mut bytes, 18, 62, Data::Little);
        put_u32(&mut bytes, 20, 1, Data::Little);
        put_u64(&mut bytes, 32, phoff, Data::Little);
        put_u16(&mut bytes, 52, 64, Data::Little);
        put_u16(&mut bytes, 54, 56, Data::Little);
        put_u16(&mut bytes, 56, phnum, Data::Little);
        bytes
    }

    struct Extra<'a> {
        soname: Option<&'a str>,
        filter: &'a [&'a str],
        auxiliary: &'a [&'a str],
        flags: u64,
        symbolic: bool,
        textrel: bool,
        bind_now: bool,
    }

    impl Extra<'static> {
        fn none() -> Self {
            Self {
                soname: None,
                filter: &[],
                auxiliary: &[],
                flags: 0,
                symbolic: false,
                textrel: false,
                bind_now: false,
            }
        }
    }

    fn elf_with_dynamic(ty: Type, flags1: u64, interp: Option<&str>, needed: &[&str]) -> Vec<u8> {
        elf_with_dynamic_endian(
            Data::Little,
            ty,
            flags1,
            interp,
            needed,
            None,
            None,
            Extra::none(),
        )
    }

    fn elf_with_dynamic_endian(
        data: Data,
        ty: Type,
        flags1: u64,
        interp: Option<&str>,
        needed: &[&str],
        runpath: Option<&str>,
        rpath: Option<&str>,
        extra: Extra<'_>,
    ) -> Vec<u8> {
        let mut names = Vec::new();
        let mut needed_at = Vec::new();
        for name in needed {
            needed_at.push(names.len() as u64);
            names.extend(name.as_bytes());
            names.push(0);
        }
        let run_at = runpath.map(|text| push_name(&mut names, text));
        let r_at = rpath.map(|text| push_name(&mut names, text));
        let soname_at = extra.soname.map(|text| push_name(&mut names, text));
        let mut filter_at = Vec::new();
        for name in extra.filter {
            filter_at.push(push_name(&mut names, name));
        }
        let mut auxiliary_at = Vec::new();
        for name in extra.auxiliary {
            auxiliary_at.push(push_name(&mut names, name));
        }
        if names.is_empty() {
            names.push(0);
        }
        let interp_bytes = interp.map(|path| {
            let mut bytes = path.as_bytes().to_vec();
            bytes.push(0);
            bytes
        });
        let phnum: u16 = if interp_bytes.is_some() { 3 } else { 2 };
        let ph_bytes = phnum as usize * 56;
        let extra_n = run_at.is_some() as usize
            + r_at.is_some() as usize
            + soname_at.is_some() as usize
            + filter_at.len()
            + auxiliary_at.len()
            + (extra.flags != 0) as usize
            + extra.symbolic as usize
            + extra.textrel as usize
            + extra.bind_now as usize;
        let dyn_entries = 3 + needed.len() + extra_n;
        let dyn_bytes = dyn_entries * 16;
        let header_len = 64;
        let dyn_off = header_len + ph_bytes;
        let str_off = dyn_off + dyn_bytes;
        let interp_off = str_off + names.len();
        let mut bytes = vec![0u8; interp_off + interp_bytes.as_ref().map(|b| b.len()).unwrap_or(0)];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = if data == Data::Little { 1 } else { 2 };
        bytes[6] = 1;
        put_u16(&mut bytes, 16, type_byte(ty), data);
        put_u16(&mut bytes, 18, 62, data);
        put_u32(&mut bytes, 20, 1, data);
        put_u64(&mut bytes, 32, header_len as u64, data);
        put_u16(&mut bytes, 52, 64, data);
        put_u16(&mut bytes, 54, 56, data);
        put_u16(&mut bytes, 56, phnum, data);
        let filesz = bytes.len() as u64;
        write_load(&mut bytes, header_len, 0, 0, filesz, data);
        write_dynamic(
            &mut bytes,
            header_len + 56,
            dyn_off as u64,
            dyn_bytes as u64,
            data,
        );
        if interp_bytes.is_some() {
            write_interp(
                &mut bytes,
                header_len + 112,
                interp_off as u64,
                interp_bytes.as_ref().unwrap().len() as u64,
                data,
            );
        }
        write_dyn_table(
            &mut bytes,
            dyn_off,
            str_off as u64,
            flags1,
            &needed_at,
            run_at,
            r_at,
            soname_at,
            &filter_at,
            &auxiliary_at,
            &extra,
            data,
        );
        bytes[str_off..str_off + names.len()].copy_from_slice(&names);
        if let Some(text) = interp_bytes {
            bytes[interp_off..interp_off + text.len()].copy_from_slice(&text);
        }
        bytes
    }

    fn write_load(bytes: &mut [u8], at: usize, offset: u64, vaddr: u64, filesz: u64, data: Data) {
        put_u32(bytes, at, PT_LOAD, data);
        put_u64(bytes, at + 8, offset, data);
        put_u64(bytes, at + 16, vaddr, data);
        put_u64(bytes, at + 32, filesz, data);
    }

    fn write_dynamic(bytes: &mut [u8], at: usize, offset: u64, filesz: u64, data: Data) {
        put_u32(bytes, at, PT_DYNAMIC, data);
        put_u64(bytes, at + 8, offset, data);
        put_u64(bytes, at + 16, offset, data);
        put_u64(bytes, at + 32, filesz, data);
    }

    fn write_interp(bytes: &mut [u8], at: usize, offset: u64, filesz: u64, data: Data) {
        put_u32(bytes, at, PT_INTERP, data);
        put_u64(bytes, at + 8, offset, data);
        put_u64(bytes, at + 16, offset, data);
        put_u64(bytes, at + 32, filesz, data);
    }

    fn push_name(names: &mut Vec<u8>, text: &str) -> u64 {
        let off = names.len() as u64;
        names.extend(text.as_bytes());
        names.push(0);
        off
    }

    fn write_dyn_table(
        bytes: &mut [u8],
        at: usize,
        strtab: u64,
        flags1: u64,
        needed_at: &[u64],
        run_at: Option<u64>,
        r_at: Option<u64>,
        soname_at: Option<u64>,
        filter_at: &[u64],
        auxiliary_at: &[u64],
        extra: &Extra<'_>,
        data: Data,
    ) {
        put_u64(bytes, at, DT_STRTAB, data);
        put_u64(bytes, at + 8, strtab, data);
        put_u64(bytes, at + 16, DT_FLAGS_1, data);
        put_u64(bytes, at + 24, flags1, data);
        let mut slot = at + 32;
        for name_at in needed_at {
            put_u64(bytes, slot, DT_NEEDED, data);
            put_u64(bytes, slot + 8, *name_at, data);
            slot += 16;
        }
        if let Some(name_at) = run_at {
            put_u64(bytes, slot, DT_RUNPATH, data);
            put_u64(bytes, slot + 8, name_at, data);
            slot += 16;
        }
        if let Some(name_at) = r_at {
            put_u64(bytes, slot, DT_RPATH, data);
            put_u64(bytes, slot + 8, name_at, data);
            slot += 16;
        }
        if let Some(name_at) = soname_at {
            put_u64(bytes, slot, DT_SONAME, data);
            put_u64(bytes, slot + 8, name_at, data);
            slot += 16;
        }
        for name_at in filter_at {
            put_u64(bytes, slot, DT_FILTER, data);
            put_u64(bytes, slot + 8, *name_at, data);
            slot += 16;
        }
        for name_at in auxiliary_at {
            put_u64(bytes, slot, DT_AUXILIARY, data);
            put_u64(bytes, slot + 8, *name_at, data);
            slot += 16;
        }
        if extra.flags != 0 {
            put_u64(bytes, slot, DT_FLAGS, data);
            put_u64(bytes, slot + 8, extra.flags, data);
            slot += 16;
        }
        if extra.symbolic {
            put_u64(bytes, slot, DT_SYMBOLIC, data);
            put_u64(bytes, slot + 8, 0, data);
            slot += 16;
        }
        if extra.textrel {
            put_u64(bytes, slot, DT_TEXTREL, data);
            put_u64(bytes, slot + 8, 0, data);
            slot += 16;
        }
        if extra.bind_now {
            put_u64(bytes, slot, DT_BIND_NOW, data);
            put_u64(bytes, slot + 8, 0, data);
            slot += 16;
        }
        put_u64(bytes, slot, DT_NULL, data);
    }

    fn type_byte(ty: Type) -> u16 {
        match ty {
            Type::None => 0,
            Type::Rel => 1,
            Type::Exec => 2,
            Type::Dyn => 3,
            Type::Core => 4,
            Type::Other(n) => n,
        }
    }

    fn put_u16(buf: &mut [u8], at: usize, v: u16, data: Data) {
        let b = match data {
            Data::Little => v.to_le_bytes(),
            Data::Big => v.to_be_bytes(),
        };
        buf[at..at + 2].copy_from_slice(&b);
    }

    fn put_u32(buf: &mut [u8], at: usize, v: u32, data: Data) {
        let b = match data {
            Data::Little => v.to_le_bytes(),
            Data::Big => v.to_be_bytes(),
        };
        buf[at..at + 4].copy_from_slice(&b);
    }

    fn put_u64(buf: &mut [u8], at: usize, v: u64, data: Data) {
        let b = match data {
            Data::Little => v.to_le_bytes(),
            Data::Big => v.to_be_bytes(),
        };
        buf[at..at + 8].copy_from_slice(&b);
    }
}
