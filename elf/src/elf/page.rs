//! One page for one ELF header. Fields sit under the ladder rungs.
//! Each line is `key: value  # note`. This file does not read ELF bytes.
//! Color is Carbonfox, and only when the caller asks for it.

use super::header::{Class, Data, Header, Type};
use super::load::{self, Load};
use super::words::{class_name, data_name, machine_name, osabi_name, type_name};
use crate::claim;
use crate::style;
use std::fmt::Write;

pub fn render(file: &str, header: &Header, load: &Load, color: bool) -> String {
    let wide = match header.class {
        Class::Elf32 => "4 bytes.",
        Class::Elf64 => "8 bytes.",
    };
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
        "elf",
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
    where_rung(&mut out, header, wide, color);

    style::blank(&mut out);
    section_rung(&mut out, header, wide, color);
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
    ident_field(out, header, color);
    style::field(
        out,
        color,
        2,
        "class",
        class_name(header.class),
        "1 byte. Address width.",
        style::FG,
        true,
    );
    let data_fg = match header.data {
        Data::Little => style::BLUE,
        Data::Big => style::TEAL,
    };
    style::field(
        out,
        color,
        2,
        "data",
        data_name(header.data),
        "1 byte. Byte order of every multi-byte number.",
        data_fg,
        false,
    );
    style::field(
        out,
        color,
        2,
        "ei_version",
        &header.ei_version.to_string(),
        "1 byte. 1 is current.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "osabi",
        &header.os_abi.to_string(),
        "1 byte. 0 is System V. 3 is Linux.",
        style::WHITE,
        false,
    );
    let osabi = osabi_name(header.os_abi);
    let (fg, bold) = style::word_tone(osabi, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "osabi_name",
        osabi.unwrap_or("null"),
        "Word for the osabi number.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "abi_version",
        &header.abi_version.to_string(),
        "1 byte. Usually 0.",
        style::WHITE,
        false,
    );
    let (fg, bold) = type_tone(header.kind);
    style::field(
        out,
        color,
        2,
        "e_type",
        &type_name(header.kind),
        "2 bytes. The kernel runs EXEC and DYN.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "e_machine",
        &header.machine.to_string(),
        "2 bytes. Target CPU.",
        style::BLUE,
        true,
    );
    let machine = machine_name(header.machine);
    let (fg, bold) = style::word_tone(machine, style::BLUE, true);
    style::field(
        out,
        color,
        2,
        "e_machine_name",
        machine.unwrap_or("null"),
        "Word for the CPU number.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "e_version",
        &header.version.to_string(),
        "4 bytes. 1 is current.",
        style::WHITE,
        false,
    );
    let (fg, bold) = style::number_tone(header.flags as u64, style::TEAL, false);
    style::field(
        out,
        color,
        2,
        "e_flags",
        &format!("0x{:x}", header.flags),
        "4 bytes. CPU flags. Often 0.",
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
    let interp = load.interp.as_deref().unwrap_or("null");
    let (fg, bold) = if load.interp.is_some() {
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
        "PIE bit in DT_FLAGS_1.",
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
        "Rung 2. Size of this header and size of one program header.",
        style::BLUE,
        true,
    );
    style::field(
        out,
        color,
        2,
        "e_ehsize",
        &header.ehsize.to_string(),
        "2 bytes. Size of this header.",
        style::WHITE,
        false,
    );
    let (fg, bold) = style::number_tone(header.phentsize as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "e_phentsize",
        &header.phentsize.to_string(),
        "2 bytes. Size of one program header.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(header.phnum as u64, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "e_phnum",
        &header.phnum.to_string(),
        "2 bytes. Number of program headers.",
        fg,
        bold,
    );
}

fn where_rung(out: &mut String, header: &Header, wide: &str, color: bool) {
    style::rung(
        out,
        color,
        "where",
        "Assumed entry address and program-header offset.",
        style::FG,
        true,
    );
    let (fg, bold) = style::number_tone(header.entry, style::FG, true);
    style::field(
        out,
        color,
        2,
        "e_entry",
        &format!("0x{:x}", header.entry),
        &format!("{wide} Assumed address of the first instruction."),
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(header.phoff, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "e_phoff",
        &header.phoff.to_string(),
        &format!("{wide} File offset of the program headers."),
        fg,
        bold,
    );
}

fn section_rung(out: &mut String, header: &Header, wide: &str, color: bool) {
    style::rung(
        out,
        color,
        "sections",
        "The kernel does not read these fields to start the program.",
        style::LABEL,
        false,
    );
    let (fg, bold) = style::number_tone(header.shoff, style::WHITE, false);
    style::field(
        out,
        color,
        2,
        "e_shoff",
        &header.shoff.to_string(),
        &format!("{wide} File offset of the section headers."),
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "e_shentsize",
        &header.shentsize.to_string(),
        "2 bytes. Size of one section header.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "e_shnum",
        &header.shnum.to_string(),
        "2 bytes. Number of section headers.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "e_shstrndx",
        &header.shstrndx.to_string(),
        "2 bytes. Index of the section-name section.",
        style::WHITE,
        false,
    );
}

fn ident_field(out: &mut String, header: &Header, color: bool) {
    let shown = ident_text(&header.ident);
    let split = magic_end(&shown);
    let key = style::paint(color, "e_ident:", style::LABEL, false);
    let magic = style::paint(color, &shown[..split], style::GREEN, false);
    let rest = style::paint(color, &shown[split..], style::LABEL, false);
    let width = 2 + "e_ident: ".len() + shown.chars().count();
    let pad = " ".repeat(style::COLUMN.saturating_sub(width));
    let note = style::paint(
        color,
        "# 16 bytes. Magic, class, and byte order.",
        style::NOTE,
        false,
    );
    let _ = writeln!(out, "  {key} {magic}{rest}{pad}  {note}");
}

fn ident_text(bytes: &[u8; 16]) -> String {
    let mut out = String::from("[");
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&byte.to_string());
    }
    out.push(']');
    out
}

fn magic_end(text: &str) -> usize {
    let mut commas = 0;
    for (i, c) in text.char_indices() {
        if c == ',' {
            commas += 1;
            if commas == 4 {
                return i;
            }
        }
    }
    text.len()
}

fn type_tone(kind: Type) -> (style::Rgb, bool) {
    match kind {
        Type::None => (style::LABEL, false),
        Type::Rel => (style::TEAL, false),
        Type::Exec => (style::GREEN, true),
        Type::Dyn => (style::CYAN, true),
        Type::Core => (style::MAGENTA, true),
        Type::Other(_) => (style::PINK, false),
    }
}

#[cfg(test)]
mod tests {
    use super::super::header::{sample, Class, Data, Type};
    use super::super::load::{Kind, Load};
    use super::*;

    fn still() -> Load {
        Load {
            kind: Kind::Static,
            interp: None,
            needed: Vec::new(),
            pie: false,
        }
    }

    fn hash_at(text: &str, key: &str) -> usize {
        text.lines()
            .find(|line| line.starts_with(key))
            .unwrap()
            .find('#')
            .unwrap()
    }

    #[test]
    fn notes_align_under_the_rungs() {
        let text = render(
            "exec-x86-64",
            &sample(Class::Elf64, Type::Exec),
            &still(),
            false,
        );
        assert!(text.lines().any(|line| line.starts_with("type:")), "{text}");
        assert!(
            text.lines().any(|line| line.starts_with("sizes:")),
            "{text}"
        );
        assert!(
            text.lines().any(|line| line.starts_with("where:")),
            "{text}"
        );
        assert!(
            text.lines().any(|line| line.starts_with("sections:")),
            "{text}"
        );
        assert!(text.contains("# Rung 1. Magic, word size, byte order, CPU, and file type."));
        assert!(text.contains("# Rung 2. Size of this header and size of one program header."));
        assert!(text.contains("e_type: EXEC"), "{text}");
        assert!(text.lines().any(|line| line.starts_with("load:")), "{text}");
        assert!(text.contains("format: elf"), "{text}");
        assert!(text.contains("kind: static"), "{text}");
        assert!(text.contains("needed: []"), "{text}");
        assert!(text.contains("pie: false"), "{text}");
        assert!(text.contains("hermetic: true"), "{text}");
        assert!(
            text.contains("says: This program starts itself and names no other file."),
            "{text}"
        );
        assert!(text.contains("e_entry: 0x1000"), "{text}");
        assert!(
            text.contains("# 8 bytes. Assumed address of the first instruction."),
            "{text}"
        );
        assert_eq!(hash_at(&text, "type:"), hash_at(&text, "  class:"));
        assert_eq!(hash_at(&text, "sizes:"), hash_at(&text, "  e_ehsize:"));
        assert!(hash_at(&text, "  e_ident:") > hash_at(&text, "  class:"));
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    #[test]
    fn elf32_note_says_four_bytes() {
        let text = render(
            "exec-i386",
            &sample(Class::Elf32, Type::Dyn),
            &still(),
            false,
        );
        assert!(text.contains("class: ELF32"), "{text}");
        assert!(
            text.contains("# 4 bytes. Assumed address of the first instruction."),
            "{text}"
        );
    }

    #[test]
    fn null_name_and_a_hash_in_the_path() {
        let mut header = sample(Class::Elf64, Type::Exec);
        header.machine = 1;
        header.data = Data::Big;
        let text = render("a#b", &header, &still(), false);
        assert!(text.contains("data: big-endian"), "{text}");
        assert!(text.contains("e_machine_name: null"), "{text}");
        assert!(text.contains("file: \"a#b\""), "{text}");
        assert!(text.contains("# Path of this file."), "{text}");
    }

    #[test]
    fn carbonfox_colors_the_rungs() {
        let text = render(
            "exec-x86-64",
            &sample(Class::Elf64, Type::Exec),
            &still(),
            true,
        );
        assert!(text.contains("\u{1b}[1;38;2;37;190;106mtype"), "{text}");
        assert!(text.contains("\u{1b}[1;38;2;120;169;255msizes"), "{text}");
        assert!(text.contains("\u{1b}[1;38;2;37;190;106mEXEC"), "{text}");
        assert!(
            text.contains("\u{1b}[38;2;37;190;106m[127, 69, 76, 70"),
            "{text}"
        );
        assert!(text.contains("38;2;182;184;187m# "), "{text}");
        assert!(text.contains("\u{1b}[38;2;123;124;126msections"), "{text}");
        assert!(!text.contains("\u{1b}[2m"), "{text}");
    }
}
