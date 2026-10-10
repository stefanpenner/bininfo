//! One JSON object for one ELF header.
//! This file does not read ELF bytes.

use super::header::Header;
use super::load::Load;
use super::words::{class_name, data_name, machine_name, osabi_name, type_name};
use crate::claim;
use crate::style::Json;

pub fn render(file: &str, header: &Header, load: &Load) -> String {
    let mut out = Json::new();
    out.str("file", file);
    out.str("format", "elf");
    out.u8s("e_ident", &header.ident);
    out.str("class", class_name(header.class));
    out.str("data", data_name(header.data));
    out.u64("ei_version", header.ei_version as u64);
    out.u64("osabi", header.os_abi as u64);
    out.opt("osabi_name", osabi_name(header.os_abi));
    out.u64("abi_version", header.abi_version as u64);
    out.str("e_type", &type_name(header.kind));
    out.u64("e_machine", header.machine as u64);
    out.opt("e_machine_name", machine_name(header.machine));
    out.u64("e_version", header.version as u64);
    out.u64("e_entry", header.entry);
    out.u64("e_phoff", header.phoff);
    out.u64("e_shoff", header.shoff);
    out.u64("e_flags", header.flags as u64);
    out.u64("e_ehsize", header.ehsize as u64);
    out.u64("e_phentsize", header.phentsize as u64);
    out.u64("e_phnum", header.phnum as u64);
    out.u64("e_shentsize", header.shentsize as u64);
    out.u64("e_shnum", header.shnum as u64);
    out.u64("e_shstrndx", header.shstrndx as u64);
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

    #[test]
    fn one_object_uses_elf_names() {
        let text = render("exec-x86-64", &sample(Class::Elf64, Type::Exec), &still());
        assert_eq!(
            text,
            concat!(
                r#"{"file":"exec-x86-64","format":"elf","e_ident":[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0],"#,
                r#""class":"ELF64","data":"little-endian","ei_version":1,"osabi":0,"#,
                r#""osabi_name":"System V","abi_version":0,"e_type":"EXEC","e_machine":62,"#,
                r#""e_machine_name":"x86-64","e_version":1,"e_entry":4096,"e_phoff":64,"#,
                r#""e_shoff":0,"e_flags":0,"e_ehsize":64,"e_phentsize":56,"e_phnum":1,"#,
                r#""e_shentsize":0,"e_shnum":0,"e_shstrndx":0,"#,
                r#""load":{"kind":"static","interp":null,"needed":[],"pie":false,"hermetic":true,"says":"This program starts itself and names no other file."}}"#,
                "\n"
            )
        );
    }

    #[test]
    fn elf32_and_big_endian_keep_their_names() {
        let elf32 = render("exec-i386", &sample(Class::Elf32, Type::Dyn), &still());
        assert!(elf32.contains(r#""class":"ELF32""#), "{elf32}");
        assert!(elf32.contains(r#""e_type":"DYN""#), "{elf32}");
        assert!(elf32.contains(r#""e_ehsize":52"#), "{elf32}");

        let mut header = sample(Class::Elf64, Type::Exec);
        header.data = Data::Big;
        let big = render("exec-powerpc64", &header, &still());
        assert!(big.contains(r#""data":"big-endian""#), "{big}");
    }

    #[test]
    fn unknown_names_are_null_and_paths_are_escaped() {
        let mut header = sample(Class::Elf64, Type::Other(99));
        header.machine = 1;
        header.os_abi = 9;
        let text = render("a\"b\\c\n", &header, &still());
        assert!(text.starts_with("{\"file\":\"a\\\"b\\\\c\\n\""), "{text}");
        assert!(text.contains(r#""format":"elf""#), "{text}");
        assert!(text.contains(r#""e_type":"99""#), "{text}");
        assert!(
            text.contains(r#""e_machine":1,"e_machine_name":null"#),
            "{text}"
        );
        assert!(text.contains(r#""osabi":9,"osabi_name":null"#), "{text}");
    }
}
