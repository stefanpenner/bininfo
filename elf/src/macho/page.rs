//! One page for one Mach-O header. Fields sit under the same rungs as ELF.
//! This file does not read Mach-O bytes.

use super::header::{Fat, FileType, Image, Thin};
use super::load::{self, Commands};
use super::words::{class_name, cpu_name, data_name, file_name, slice_labels};
use crate::claim;
use crate::style;

pub fn render(file: &str, image: &Image, commands: &Commands, color: bool) -> String {
    let mut out = String::new();
    style::field(
        &mut out,
        color,
        0,
        "file",
        file,
        "Path of this file.",
        style::WHITE,
        false,
    );
    style::field(
        &mut out,
        color,
        0,
        "format",
        "macho",
        "elf, macho, or pe.",
        style::FG,
        true,
    );
    style::blank(&mut out);
    match image {
        Image::Thin(thin) => thin_page(&mut out, thin, commands, color),
        Image::Fat(fat) => fat_page(&mut out, fat, commands, color),
    }
    out
}

fn thin_page(out: &mut String, thin: &Thin, commands: &Commands, color: bool) {
    type_rung(out, thin, color);
    style::blank(out);
    load_rung(out, commands, color);
    style::blank(out);
    size_rung(out, thin, color);
    style::blank(out);
    where_rung(out, thin, commands, color);
    style::blank(out);
    section_rung(out, commands, color);
}

fn fat_page(out: &mut String, fat: &Fat, commands: &Commands, color: bool) {
    style::rung(
        out,
        color,
        "type",
        "Rung 1. Magic, word size, byte order, CPU, and file type.",
        style::GREEN,
        true,
    );
    style::field(
        out,
        color,
        2,
        "magic",
        &format!("0x{:x}", fat.magic),
        "4 bytes. Mach-O mark.",
        style::GREEN,
        false,
    );
    style::field(
        out,
        color,
        2,
        "class",
        class_name(fat.class),
        "A fat file holds more than one Mach-O.",
        style::FG,
        true,
    );
    style::field(
        out,
        color,
        2,
        "data",
        data_name(fat.data),
        "Byte order of every multi-byte number.",
        style::BLUE,
        false,
    );
    style::raw_field(
        out,
        color,
        2,
        "slices",
        &style::yaml_list(&slice_labels(fat)),
        "CPU, file offset, and byte size of one slice.",
        if fat.arches.is_empty() {
            style::LABEL
        } else {
            style::WHITE
        },
        false,
    );
    style::blank(out);
    load_rung(out, commands, color);
    style::blank(out);
    style::rung(
        out,
        color,
        "sizes",
        "Rung 2. Size of this header and size of one slice.",
        style::BLUE,
        true,
    );
    style::field(
        out,
        color,
        2,
        "header_size",
        &fat.class.header_bytes().to_string(),
        "Bytes in this header.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "arch_size",
        &fat.class.arch_bytes().to_string(),
        "Bytes in one slice header.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "nfat_arch",
        &fat.nfat_arch.to_string(),
        "4 bytes. Number of slices.",
        style::WHITE,
        false,
    );
    style::blank(out);
    let off = fat.arches.first().map(|arch| arch.offset).unwrap_or(0);
    style::rung(
        out,
        color,
        "where",
        "File offset of the first slice.",
        style::FG,
        true,
    );
    let (fg, bold) = style::number_tone(off, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "slice_off",
        &format!("0x{off:x}"),
        "File offset of the first slice.",
        fg,
        bold,
    );
    style::blank(out);
    style::rung(
        out,
        color,
        "sections",
        "This page does not open a slice.",
        style::LABEL,
        false,
    );
}

fn type_rung(out: &mut String, thin: &Thin, color: bool) {
    style::rung(
        out,
        color,
        "type",
        "Rung 1. Magic, word size, byte order, CPU, and file type.",
        style::GREEN,
        true,
    );
    style::field(
        out,
        color,
        2,
        "magic",
        &format!("0x{:x}", thin.magic),
        "4 bytes. Mach-O mark.",
        style::GREEN,
        false,
    );
    style::field(
        out,
        color,
        2,
        "class",
        class_name(thin.class),
        "Address width.",
        style::FG,
        true,
    );
    let data_fg = match thin.data {
        super::header::Data::Little => style::BLUE,
        super::header::Data::Big => style::TEAL,
    };
    style::field(
        out,
        color,
        2,
        "data",
        data_name(thin.data),
        "Byte order of every multi-byte number.",
        data_fg,
        false,
    );
    style::field(
        out,
        color,
        2,
        "cputype",
        &thin.cputype.to_string(),
        "4 bytes. Target CPU.",
        style::BLUE,
        true,
    );
    let cpu = cpu_name(thin.cputype);
    let (fg, bold) = style::word_tone(cpu, style::BLUE, true);
    style::field(
        out,
        color,
        2,
        "cputype_name",
        cpu.unwrap_or("null"),
        "Word for the CPU number.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "cpusubtype",
        &thin.cpusubtype.to_string(),
        "4 bytes. CPU variant.",
        style::WHITE,
        false,
    );
    let (fg, bold) = file_tone(thin.filetype);
    style::field(
        out,
        color,
        2,
        "filetype",
        &file_name(thin.filetype),
        "4 bytes. MH_EXECUTE, MH_DYLIB, or MH_OBJECT.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(thin.flags as u64, style::TEAL, false);
    style::field(
        out,
        color,
        2,
        "flags",
        &format!("0x{:x}", thin.flags),
        "4 bytes. Header flags. MH_PIE is 0x200000.",
        fg,
        bold,
    );
}

fn load_rung(out: &mut String, commands: &Commands, color: bool) {
    style::rung(
        out,
        color,
        "load",
        "How this file starts, and which files it must open.",
        style::FG,
        true,
    );
    let (fg, bold) = style::kind_tone(commands.load.kind);
    style::field(
        out,
        color,
        2,
        "kind",
        load::kind_name(commands.load.kind),
        load::kind_note(commands.load.kind),
        fg,
        bold,
    );
    let interp = commands.load.interp.as_deref().unwrap_or("null");
    let (fg, bold) = if commands.load.interp.is_some() {
        (style::WHITE, false)
    } else {
        (style::LABEL, false)
    };
    style::field(
        out,
        color,
        2,
        "interp",
        interp,
        "Path of the loader. null means this file starts itself.",
        fg,
        bold,
    );
    style::raw_field(
        out,
        color,
        2,
        "needed",
        &style::yaml_list(&commands.load.needed),
        "Library names the loader opens.",
        if commands.load.needed.is_empty() {
            style::LABEL
        } else {
            style::WHITE
        },
        false,
    );
    style::field(
        out,
        color,
        2,
        "pie",
        if commands.load.pie { "true" } else { "false" },
        "MH_PIE bit in the header flags.",
        if commands.load.pie {
            style::GREEN
        } else {
            style::LABEL
        },
        commands.load.pie,
    );
    claim::write_tail(
        out,
        color,
        commands.load.kind,
        commands.load.interp.as_deref(),
        &commands.load.needed,
    );
}

fn size_rung(out: &mut String, thin: &Thin, color: bool) {
    style::rung(
        out,
        color,
        "sizes",
        "Rung 2. Size of this header and size of the load commands.",
        style::BLUE,
        true,
    );
    style::field(
        out,
        color,
        2,
        "header_size",
        &thin.class.header_bytes().to_string(),
        "Bytes in this header. 28 or 32.",
        style::WHITE,
        false,
    );
    let (fg, bold) = style::number_tone(thin.ncmds as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "ncmds",
        &thin.ncmds.to_string(),
        "4 bytes. Number of load commands.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(thin.sizeofcmds as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "sizeofcmds",
        &thin.sizeofcmds.to_string(),
        "4 bytes. Byte size of all load commands.",
        fg,
        bold,
    );
}

fn where_rung(out: &mut String, thin: &Thin, commands: &Commands, color: bool) {
    let wide = if commands.entry_is_offset || thin.class != super::header::Class::Mach32 {
        "8 bytes."
    } else {
        "4 bytes."
    };
    let entry_note = if commands.entry_is_offset {
        format!("{wide} File offset of the entry point.")
    } else {
        format!("{wide} Assumed address of the first instruction.")
    };
    style::rung(
        out,
        color,
        "where",
        "Entry and load-command offset.",
        style::FG,
        true,
    );
    let (fg, bold) = style::number_tone(commands.entry, style::FG, true);
    style::field(
        out,
        color,
        2,
        "entry",
        &format!("0x{:x}", commands.entry),
        &entry_note,
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "cmdoff",
        &thin.class.header_bytes().to_string(),
        "File offset of the load commands.",
        style::WHITE,
        false,
    );
}

fn section_rung(out: &mut String, commands: &Commands, color: bool) {
    style::rung(
        out,
        color,
        "sections",
        "The loader does not read the symbol table to start the program.",
        style::LABEL,
        false,
    );
    let (fg, bold) = style::number_tone(commands.symoff as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "symoff",
        &commands.symoff.to_string(),
        "4 bytes. File offset of the symbol table.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "nsyms",
        &commands.nsyms.to_string(),
        "4 bytes. Number of symbols.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "stroff",
        &commands.stroff.to_string(),
        "4 bytes. File offset of the string table.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "strsize",
        &commands.strsize.to_string(),
        "4 bytes. Byte size of the string table.",
        style::WHITE,
        false,
    );
}

fn file_tone(kind: FileType) -> (style::Rgb, bool) {
    match kind {
        FileType::Object => (style::TEAL, false),
        FileType::Execute => (style::GREEN, true),
        FileType::Dylib | FileType::Bundle => (style::MAGENTA, true),
        FileType::Dylinker => (style::BLUE, true),
        FileType::Core => (style::MAGENTA, true),
        _ => (style::PINK, false),
    }
}

#[cfg(test)]
mod tests {
    use super::super::header::exec64;
    use super::super::load::{Commands, Kind, Load};
    use super::*;

    fn still() -> Commands {
        Commands {
            load: Load {
                kind: Kind::Static,
                interp: None,
                needed: Vec::new(),
                pie: false,
            },
            entry: 0x1000,
            entry_is_offset: true,
            symoff: 0,
            nsyms: 0,
            stroff: 0,
            strsize: 0,
        }
    }

    #[test]
    fn notes_use_the_same_rungs() {
        let text = render("exec", &exec64(), &still(), false);
        for key in ["type:", "load:", "sizes:", "where:", "sections:"] {
            assert!(text.lines().any(|line| line.starts_with(key)), "{text}");
        }
        assert!(text.contains("format: macho"), "{text}");
        assert!(text.contains("filetype: EXECUTE"), "{text}");
        assert!(text.contains("kind: static"), "{text}");
        assert!(text.contains("needed: []"), "{text}");
        assert!(text.contains("hermetic: true"), "{text}");
        assert!(
            text.contains("says: This program starts itself and names no other file."),
            "{text}"
        );
        assert!(text.contains("# MH_PIE bit in the header flags."), "{text}");
        assert!(
            text.contains("# 8 bytes. File offset of the entry point."),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");
    }
}
