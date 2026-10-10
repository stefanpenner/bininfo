//! One JSON object for one PE header.
//! This file does not read PE bytes.

use super::header::Header;
use super::load::Load;
use super::words::{class_name, machine_name, magic_name, subsystem_name};
use crate::claim;
use crate::style::Json;

pub fn render(file: &str, header: &Header, load: &Load) -> String {
    let mut out = Json::new();
    out.str("file", file);
    out.str("format", "pe");
    if header.dos == 0 {
        out.opt("magic", None);
    } else {
        out.str("magic", magic_name(header.dos));
    }
    out.opt(
        "signature",
        if header.class == super::header::Class::Coff {
            None
        } else {
            Some("PE")
        },
    );
    out.str("class", class_name(header.class));
    out.str("data", "little-endian");
    out.u64("machine", header.machine as u64);
    out.opt("machine_name", machine_name(header.machine));
    out.u64("characteristics", header.characteristics as u64);
    out.u64("subsystem", header.subsystem as u64);
    out.opt("subsystem_name", subsystem_name(header.subsystem));
    out.u64("dll_characteristics", header.dll_characteristics as u64);
    out.u64("size_of_optional_header", header.opt_size as u64);
    out.u64("number_of_sections", header.sections as u64);
    out.u64("size_of_headers", header.size_of_headers as u64);
    out.u64("entry", header.entry as u64);
    out.u64("image_base", header.image_base);
    out.u64("e_lfanew", header.lfanew as u64);
    out.u64("pointer_to_symbol_table", header.symoff as u64);
    out.u64("number_of_symbols", header.nsyms as u64);
    claim::write_load(
        &mut out,
        load.kind,
        load.interp.as_deref(),
        &load.needed,
        load.pie,
    );
    out.finish()
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
            lfanew: 0x40,
            machine: 0x8664,
            sections: 1,
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
    fn one_object_uses_pe_names() {
        let text = render("exec.exe", &exe(), &still());
        assert!(text.contains(r#""format":"pe""#), "{text}");
        assert!(text.contains(r#""magic":"MZ""#), "{text}");
        assert!(text.contains(r#""class":"PE32+""#), "{text}");
        assert!(text.contains(r#""machine_name":"x86-64""#), "{text}");
        assert!(
            text.contains(r#""load":{"kind":"static-pie","interp":null,"needed":[],"pie":true,"hermetic":true,"says":"This program starts itself and names no other file."}"#),
            "{text}"
        );
        assert_eq!(text.matches('{').count(), 2, "{text}");
    }
}
