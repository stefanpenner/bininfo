//! How a Mach-O file starts, and which files it must open.
//! This module reads load commands. It does not print them.

use super::header::{self, Class, Data, FileType, Image, Thin};
pub(crate) use crate::kind::name as kind_name;
pub use crate::kind::Kind;

const LC_SYMTAB: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
const LC_REEXPORT_DYLIB: u32 = 0x1f;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23;
const LC_MAIN: u32 = 0x28;
const LC_REQ: u32 = 0x8000_0000;
const MH_PIE: u32 = 0x0020_0000;
const NAME_CAP: usize = 4096;

/// Facts that match the ELF load map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Load {
    pub kind: Kind,
    pub interp: Option<String>, // LC_LOAD_DYLINKER path. None means this file starts itself.
    pub needed: Vec<String>,    // Dylib names the loader opens.
    pub pie: bool,              // MH_PIE bit in the header flags.
}

/// Load-command facts. `entry` is not in the Mach-O header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commands {
    pub load: Load,
    pub entry: u64,            // LC_MAIN file offset, or a thread-state address.
    pub entry_is_offset: bool, // True when entry comes from LC_MAIN.
    pub symoff: u32,           // LC_SYMTAB. The loader does not need this.
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

pub fn read(bytes: &[u8], image: &Image) -> Commands {
    let Image::Thin(thin) = image else {
        return blank(Kind::Other);
    };
    let mut commands = blank(Kind::Other);
    let mut saw_main = false;
    let start = thin.class.header_bytes() as usize;
    let end = start
        .saturating_add(thin.sizeofcmds as usize)
        .min(bytes.len());
    let mut at = start;
    let mut seen = 0u32;
    while seen < thin.ncmds {
        let Some(cmd) = header::u32_at(bytes, at, thin.data) else {
            break;
        };
        let Some(size) = header::u32_at(bytes, at + 4, thin.data) else {
            break;
        };
        if size < 8 {
            break;
        }
        let Some(next) = at.checked_add(size as usize) else {
            break;
        };
        if next > end || next > bytes.len() {
            break;
        }
        match cmd & !LC_REQ {
            LC_LOAD_DYLINKER => {
                if let Some(path) = cmd_name(bytes, at, size, thin.data) {
                    commands.load.interp = Some(path);
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                if let Some(name) = cmd_name(bytes, at, size, thin.data) {
                    commands.load.needed.push(name);
                }
            }
            LC_MAIN => {
                if let Some(entry) = header::u64_at(bytes, at + 8, thin.data) {
                    commands.entry = entry;
                    commands.entry_is_offset = true;
                    saw_main = true;
                }
            }
            LC_UNIXTHREAD if !saw_main => {
                if let Some(pc) = thread_pc(bytes, at, size, thin) {
                    commands.entry = pc;
                    commands.entry_is_offset = false;
                }
            }
            LC_SYMTAB if size >= 24 => {
                commands.symoff = header::u32_at(bytes, at + 8, thin.data).unwrap_or(0);
                commands.nsyms = header::u32_at(bytes, at + 12, thin.data).unwrap_or(0);
                commands.stroff = header::u32_at(bytes, at + 16, thin.data).unwrap_or(0);
                commands.strsize = header::u32_at(bytes, at + 20, thin.data).unwrap_or(0);
            }
            _ => {}
        }
        at = next;
        seen += 1;
    }
    let pie = thin.flags & MH_PIE != 0;
    commands.load.pie = pie;
    commands.load.kind = classify(thin.filetype, commands.load.interp.is_some(), pie);
    commands
}

pub(crate) fn kind_note(kind: Kind) -> &'static str {
    match kind {
        Kind::Static => "MH_EXECUTE and no loader.",
        Kind::Dynamic => "A loader is present and the PIE bit is clear.",
        Kind::DynamicPie => "A loader is present and the PIE bit is set.",
        Kind::StaticPie => "MH_EXECUTE, no loader, and the PIE bit is set.",
        Kind::Shared => "A shared library or a bundle.",
        Kind::Rel => "MH_OBJECT. The kernel does not run this file.",
        Kind::Other => "This file type is outside the four start kinds.",
    }
}

fn classify(ty: FileType, interp: bool, pie: bool) -> Kind {
    match ty {
        FileType::Object => Kind::Rel,
        FileType::Execute if interp && pie => Kind::DynamicPie,
        FileType::Execute if interp => Kind::Dynamic,
        FileType::Execute if pie => Kind::StaticPie,
        FileType::Execute => Kind::Static,
        FileType::Dylib | FileType::Bundle => Kind::Shared,
        _ => Kind::Other,
    }
}

fn blank(kind: Kind) -> Commands {
    Commands {
        load: Load {
            kind,
            interp: None,
            needed: Vec::new(),
            pie: false,
        },
        entry: 0,
        entry_is_offset: false,
        symoff: 0,
        nsyms: 0,
        stroff: 0,
        strsize: 0,
    }
}

fn cmd_name(bytes: &[u8], at: usize, size: u32, data: Data) -> Option<String> {
    let off = header::u32_at(bytes, at + 8, data)?;
    let start = at.checked_add(off as usize)?;
    let end = at.checked_add(size as usize)?.min(bytes.len());
    if start >= end {
        return None;
    }
    let take = (end - start).min(NAME_CAP);
    let slice = &bytes[start..start + take];
    let n = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    let text = String::from_utf8_lossy(&slice[..n]).into_owned();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn thread_pc(bytes: &[u8], at: usize, size: u32, thin: &Thin) -> Option<u64> {
    let flavor = header::u32_at(bytes, at + 12, thin.data)?;
    let state = at + 16;
    let end = at + size as usize;
    let read_u64 = |pos: usize| {
        if pos + 8 > end {
            None
        } else {
            header::u64_at(bytes, pos, thin.data)
        }
    };
    match flavor {
        4 => read_u64(state + 128),
        6 => read_u64(state + 256),
        1 if thin.class == Class::Mach32 => {
            if state + 44 > end {
                None
            } else {
                header::u32_at(bytes, state + 40, thin.data).map(|v| v as u64)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::header::{Data, FileType};
    use super::*;

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

    fn header(filetype: u32, flags: u32, data: Data) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        let magic: [u8; 4] = match data {
            Data::Little => [0xcf, 0xfa, 0xed, 0xfe],
            Data::Big => [0xfe, 0xed, 0xfa, 0xcf],
        };
        b[..4].copy_from_slice(&magic);
        put_u32(&mut b, 4, 0x0100_0007, data);
        put_u32(&mut b, 12, filetype, data);
        put_u32(&mut b, 24, flags, data);
        b
    }

    fn finish(buf: &mut Vec<u8>, data: Data, ncmds: u32) {
        let size = (buf.len() - 32) as u32;
        put_u32(buf, 16, ncmds, data);
        put_u32(buf, 20, size, data);
    }

    fn push_text(buf: &mut Vec<u8>, cmd: u32, name_off: u32, text: &str, data: Data) {
        let raw = name_off + text.len() as u32 + 1;
        let size = (raw + 7) & !7;
        let at = buf.len();
        buf.resize(at + size as usize, 0);
        put_u32(buf, at, cmd, data);
        put_u32(buf, at + 4, size, data);
        put_u32(buf, at + 8, name_off, data);
        let start = at + name_off as usize;
        buf[start..start + text.len()].copy_from_slice(text.as_bytes());
    }

    fn push_main(buf: &mut Vec<u8>, entry: u64, data: Data) {
        let at = buf.len();
        buf.resize(at + 24, 0);
        put_u32(buf, at, LC_MAIN | LC_REQ, data);
        put_u32(buf, at + 4, 24, data);
        put_u64(buf, at + 8, entry, data);
    }

    #[test]
    fn static_execute_names_no_loader() {
        let bytes = header(2, 0, Data::Little);
        let image = header::parse(&bytes).unwrap();
        let commands = read(&bytes, &image);
        assert_eq!(commands.load.kind, Kind::Static);
        assert!(commands.load.interp.is_none());
        assert!(commands.load.needed.is_empty());
        assert!(!commands.load.pie);
    }

    #[test]
    fn static_pie_sets_the_flag_and_names_no_loader() {
        let bytes = header(2, MH_PIE, Data::Little);
        let image = header::parse(&bytes).unwrap();
        let commands = read(&bytes, &image);
        assert_eq!(commands.load.kind, Kind::StaticPie);
        assert!(commands.load.pie);
    }

    #[test]
    fn dynamic_pie_names_the_loader_and_two_libraries() {
        let mut bytes = header(2, MH_PIE, Data::Little);
        push_text(
            &mut bytes,
            LC_LOAD_DYLINKER,
            12,
            "/usr/lib/dyld",
            Data::Little,
        );
        push_text(&mut bytes, LC_LOAD_DYLIB, 24, "liba.dylib", Data::Little);
        push_text(
            &mut bytes,
            LC_LOAD_DYLIB | LC_REQ,
            24,
            "libb.dylib",
            Data::Little,
        );
        push_main(&mut bytes, 0x1000, Data::Little);
        finish(&mut bytes, Data::Little, 4);
        let image = header::parse(&bytes).unwrap();
        let commands = read(&bytes, &image);
        assert_eq!(commands.load.kind, Kind::DynamicPie);
        assert_eq!(commands.load.interp.as_deref(), Some("/usr/lib/dyld"));
        assert_eq!(commands.load.needed, ["liba.dylib", "libb.dylib"]);
        assert!(commands.load.pie);
        assert!(commands.entry_is_offset);
        assert_eq!(commands.entry, 0x1000);
    }

    #[test]
    fn dynamic_without_the_pie_bit() {
        let mut bytes = header(2, 0, Data::Little);
        push_text(
            &mut bytes,
            LC_LOAD_DYLINKER,
            12,
            "/usr/lib/dyld",
            Data::Little,
        );
        finish(&mut bytes, Data::Little, 1);
        let image = header::parse(&bytes).unwrap();
        let commands = read(&bytes, &image);
        assert_eq!(commands.load.kind, Kind::Dynamic);
        assert!(!commands.load.pie);
    }

    #[test]
    fn shared_library_keeps_its_needed_list() {
        let mut bytes = header(6, 0, Data::Little);
        push_text(
            &mut bytes,
            LC_LOAD_DYLIB,
            24,
            "/usr/lib/libSystem.B.dylib",
            Data::Little,
        );
        finish(&mut bytes, Data::Little, 1);
        let image = header::parse(&bytes).unwrap();
        let commands = read(&bytes, &image);
        assert_eq!(commands.load.kind, Kind::Shared);
        assert!(commands.load.interp.is_none());
        assert_eq!(commands.load.needed, ["/usr/lib/libSystem.B.dylib"]);
    }

    #[test]
    fn object_file_is_rel_and_thread_state_is_an_address() {
        let mut bytes = header(1, 0, Data::Little);
        let at = bytes.len();
        bytes.resize(at + 16 + 136, 0);
        put_u32(&mut bytes, at, LC_UNIXTHREAD, Data::Little);
        put_u32(&mut bytes, at + 4, (16 + 136) as u32, Data::Little);
        put_u32(&mut bytes, at + 12, 4, Data::Little);
        put_u64(
            &mut bytes,
            at + 16 + 128,
            0x1122_3344_5566_7788,
            Data::Little,
        );
        finish(&mut bytes, Data::Little, 1);
        let image = header::parse(&bytes).unwrap();
        let commands = read(&bytes, &image);
        assert_eq!(commands.load.kind, Kind::Rel);
        assert!(!commands.entry_is_offset);
        assert_eq!(commands.entry, 0x1122_3344_5566_7788);
    }

    #[test]
    fn big_endian_dynamic_keeps_the_pie_bit() {
        let mut bytes = header(2, MH_PIE, Data::Big);
        push_text(&mut bytes, LC_LOAD_DYLINKER, 12, "/usr/lib/dyld", Data::Big);
        push_main(&mut bytes, 0x20, Data::Big);
        finish(&mut bytes, Data::Big, 2);
        let image = header::parse(&bytes).unwrap();
        let Image::Thin(thin) = &image else {
            panic!("fat")
        };
        assert_eq!(thin.data, Data::Big);
        assert_eq!(thin.filetype, FileType::Execute);
        let commands = read(&bytes, &image);
        assert_eq!(commands.load.kind, Kind::DynamicPie);
        assert_eq!(commands.entry, 0x20);
    }

    #[test]
    fn hostile_load_commands_do_not_panic() {
        let mut bytes = header(2, 0, Data::Little);
        put_u32(&mut bytes, 16, u32::MAX, Data::Little);
        put_u32(&mut bytes, 20, u32::MAX, Data::Little);
        let image = header::parse(&bytes).unwrap();
        assert!(std::panic::catch_unwind(|| read(&bytes, &image)).is_ok());
        let mut zero = header(2, 0, Data::Little);
        zero.extend_from_slice(&[0u8; 8]);
        put_u32(&mut zero, 16, 4, Data::Little);
        put_u32(&mut zero, 20, 8, Data::Little);
        let image = header::parse(&zero).unwrap();
        assert!(std::panic::catch_unwind(|| read(&zero, &image)).is_ok());
    }
}
