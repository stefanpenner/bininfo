//! One page for one PE header. Fields sit under the same rungs as ELF.
//! This file does not read PE bytes.

use super::header::{Class, Header};
use super::load::{self, Load};
use super::words::{class_name, machine_name, magic_name, subsystem_name};
use crate::claim;
use crate::style;

pub fn render(file: &str, header: &Header, load: &Load, color: bool) -> String {
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
        "pe",
        "elf, macho, or pe.",
        style::FG,
        true,
    );
    style::blank(&mut out);
    type_rung(&mut out, header, color);
    style::blank(&mut out);
    load_rung(&mut out, load, color);
    style::blank(&mut out);
    size_rung(&mut out, header, color);
    style::blank(&mut out);
    where_rung(&mut out, header, color);
    style::blank(&mut out);
    section_rung(&mut out, header, color);
    out
}

fn type_rung(out: &mut String, header: &Header, color: bool) {
    style::rung(
        out,
        color,
        "type",
        "Rung 1. Magic, word size, byte order, CPU, and file type.",
        style::GREEN,
        true,
    );
    let magic = magic_name(header.dos);
    let (fg, bold) = if magic == "null" {
        (style::LABEL, false)
    } else {
        (style::GREEN, false)
    };
    style::field(
        out,
        color,
        2,
        "magic",
        magic,
        "2 bytes. DOS mark.",
        fg,
        bold,
    );
    let sig = if header.class == Class::Coff {
        "null"
    } else {
        "PE"
    };
    let (fg, bold) = if sig == "null" {
        (style::LABEL, false)
    } else {
        (style::GREEN, true)
    };
    style::field(
        out,
        color,
        2,
        "signature",
        sig,
        "4 bytes. PE mark.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "class",
        class_name(header.class),
        "Address width.",
        style::FG,
        true,
    );
    style::field(
        out,
        color,
        2,
        "data",
        "little-endian",
        "Byte order of every multi-byte number.",
        style::BLUE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "machine",
        &header.machine.to_string(),
        "2 bytes. Target CPU.",
        style::BLUE,
        true,
    );
    let cpu = machine_name(header.machine);
    let (fg, bold) = style::word_tone(cpu, style::BLUE, true);
    style::field(
        out,
        color,
        2,
        "machine_name",
        cpu.unwrap_or("null"),
        "Word for the CPU number.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(header.characteristics as u64, style::TEAL, false);
    style::field(
        out,
        color,
        2,
        "characteristics",
        &format!("0x{:x}", header.characteristics),
        "2 bytes. EXE is 0x2. DLL is 0x2000.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "subsystem",
        &header.subsystem.to_string(),
        "2 bytes. 3 is the console.",
        style::WHITE,
        false,
    );
    let sub = subsystem_name(header.subsystem);
    let (fg, bold) = style::word_tone(sub, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "subsystem_name",
        sub.unwrap_or("null"),
        "Word for the subsystem number.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(header.dll_characteristics as u64, style::TEAL, false);
    style::field(
        out,
        color,
        2,
        "dll_characteristics",
        &format!("0x{:x}", header.dll_characteristics),
        "2 bytes. DYNAMIC_BASE is 0x40.",
        fg,
        bold,
    );
}

fn load_rung(out: &mut String, load: &Load, color: bool) {
    style::rung(
        out,
        color,
        "load",
        "How this file starts, and which files it must open.",
        style::FG,
        true,
    );
    let (fg, bold) = style::kind_tone(load.kind);
    style::field(
        out,
        color,
        2,
        "kind",
        load::kind_name(load.kind),
        load::kind_note(load.kind),
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "interp",
        "null",
        "Path of the loader. null means this file starts itself.",
        style::LABEL,
        false,
    );
    style::raw_field(
        out,
        color,
        2,
        "needed",
        &style::yaml_list(&load.needed),
        "Library names the loader opens.",
        if load.needed.is_empty() {
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
        if load.pie { "true" } else { "false" },
        "DYNAMIC_BASE bit in DllCharacteristics.",
        if load.pie { style::GREEN } else { style::LABEL },
        load.pie,
    );
    claim::write_tail(out, color, load.kind, load.interp.as_deref(), &load.needed);
}

fn size_rung(out: &mut String, header: &Header, color: bool) {
    style::rung(
        out,
        color,
        "sizes",
        "Rung 2. Size of the optional header and the section count.",
        style::BLUE,
        true,
    );
    style::field(
        out,
        color,
        2,
        "size_of_optional_header",
        &header.opt_size.to_string(),
        "2 bytes. Size of the optional header.",
        style::WHITE,
        false,
    );
    let (fg, bold) = style::number_tone(header.sections as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "number_of_sections",
        &header.sections.to_string(),
        "2 bytes. Number of sections.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(header.size_of_headers as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "size_of_headers",
        &header.size_of_headers.to_string(),
        "4 bytes. Bytes before the section bodies.",
        fg,
        bold,
    );
}

fn where_rung(out: &mut String, header: &Header, color: bool) {
    let wide = if header.class == Class::Pe32 {
        "4 bytes."
    } else {
        "8 bytes."
    };
    style::rung(
        out,
        color,
        "where",
        "Entry RVA and assumed image base.",
        style::FG,
        true,
    );
    let (fg, bold) = style::number_tone(header.entry as u64, style::FG, true);
    style::field(
        out,
        color,
        2,
        "entry",
        &format!("0x{:x}", header.entry),
        "4 bytes. RVA of the first instruction.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(header.image_base, style::FG, true);
    style::field(
        out,
        color,
        2,
        "image_base",
        &format!("0x{:x}", header.image_base),
        &format!("{wide} Assumed base address."),
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "e_lfanew",
        &header.lfanew.to_string(),
        "4 bytes. File offset of the PE signature.",
        style::WHITE,
        false,
    );
}

fn section_rung(out: &mut String, header: &Header, color: bool) {
    style::rung(
        out,
        color,
        "sections",
        "The loader does not read the COFF symbol table to start the program.",
        style::LABEL,
        false,
    );
    let (fg, bold) = style::number_tone(header.symoff as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "pointer_to_symbol_table",
        &header.symoff.to_string(),
        "4 bytes. File offset of the COFF symbols.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "number_of_symbols",
        &header.nsyms.to_string(),
        "4 bytes. Number of COFF symbols.",
        style::WHITE,
        false,
    );
}

#[cfg(test)]
mod tests {
    use super::super::header::{Class, Header};
    use super::super::load::{Kind, Load};
    use super::*;

    fn exe() -> Header {
        Header {
            class: Class::Pe32Plus,
            dos: 0x5a4d,
            lfanew: 64,
            machine: 0x8664,
            sections: 3,
            symoff: 0,
            nsyms: 0,
            opt_size: 240,
            characteristics: 0x22,
            subsystem: 3,
            dll_characteristics: 0x160,
            entry: 0x1000,
            image_base: 0x1_4000_0000,
            size_of_headers: 1024,
            opt_off: 0,
            section_off: 0,
        }
    }

    fn still() -> Load {
        Load {
            kind: Kind::StaticPie,
            interp: None,
            needed: Vec::new(),
            pie: true,
        }
    }

    #[test]
    fn notes_use_the_same_rungs() {
        let text = render("exec.exe", &exe(), &still(), false);
        for key in ["type:", "load:", "sizes:", "where:", "sections:"] {
            assert!(text.lines().any(|line| line.starts_with(key)), "{text}");
        }
        assert!(text.contains("format: pe"), "{text}");
        assert!(text.contains("class: PE32+"), "{text}");
        assert!(text.contains("kind: static-pie"), "{text}");
        assert!(text.contains("hermetic: true"), "{text}");
        assert!(
            text.contains("says: This program starts itself and names no other file."),
            "{text}"
        );
        assert!(
            text.contains("# DYNAMIC_BASE bit in DllCharacteristics."),
            "{text}"
        );
        assert!(text.contains("image_base: 0x140000000"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
    }
}
