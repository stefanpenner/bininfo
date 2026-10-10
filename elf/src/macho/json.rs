//! One JSON object for one Mach-O header.
//! This file does not read Mach-O bytes.

use super::header::{Fat, Image, Thin};
use super::load::Commands;
use super::words::{class_name, cpu_name, data_name, file_name, slice_labels};
use crate::claim;
use crate::style::Json;

pub fn render(file: &str, image: &Image, commands: &Commands) -> String {
    match image {
        Image::Thin(thin) => thin_json(file, thin, commands),
        Image::Fat(fat) => fat_json(file, fat, commands),
    }
}

fn thin_json(file: &str, thin: &Thin, commands: &Commands) -> String {
    let mut out = Json::new();
    out.str("file", file);
    out.str("format", "macho");
    out.u64("magic", thin.magic as u64);
    out.str("class", class_name(thin.class));
    out.str("data", data_name(thin.data));
    out.u64("cputype", thin.cputype as u64);
    out.opt("cputype_name", cpu_name(thin.cputype));
    out.u64("cpusubtype", thin.cpusubtype as u64);
    out.str("filetype", &file_name(thin.filetype));
    out.u64("flags", thin.flags as u64);
    out.u64("header_size", thin.class.header_bytes() as u64);
    out.u64("ncmds", thin.ncmds as u64);
    out.u64("sizeofcmds", thin.sizeofcmds as u64);
    out.u64("entry", commands.entry);
    out.u64("cmdoff", thin.class.header_bytes() as u64);
    out.u64("symoff", commands.symoff as u64);
    out.u64("nsyms", commands.nsyms as u64);
    out.u64("stroff", commands.stroff as u64);
    out.u64("strsize", commands.strsize as u64);
    write_load(&mut out, commands);
    out.finish()
}

fn fat_json(file: &str, fat: &Fat, commands: &Commands) -> String {
    let mut out = Json::new();
    out.str("file", file);
    out.str("format", "macho");
    out.u64("magic", fat.magic as u64);
    out.str("class", class_name(fat.class));
    out.str("data", data_name(fat.data));
    out.u64("nfat_arch", fat.nfat_arch as u64);
    out.u64("header_size", fat.class.header_bytes() as u64);
    out.u64("arch_size", fat.class.arch_bytes() as u64);
    out.strings("slices", &slice_labels(fat));
    write_load(&mut out, commands);
    out.finish()
}

fn write_load(out: &mut Json, commands: &Commands) {
    claim::write_load(
        out,
        commands.load.kind,
        commands.load.interp.as_deref(),
        &commands.load.needed,
        commands.load.pie,
    );
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
            entry: 0,
            entry_is_offset: false,
            symoff: 0,
            nsyms: 0,
            stroff: 0,
            strsize: 0,
        }
    }

    #[test]
    fn one_object_uses_macho_names() {
        let text = render("exec", &exec64(), &still());
        assert!(text.contains(r#""format":"macho""#), "{text}");
        assert!(text.contains(r#""class":"MH64""#), "{text}");
        assert!(text.contains(r#""filetype":"EXECUTE""#), "{text}");
        assert!(text.contains(r#""cputype_name":"AArch64""#), "{text}");
        assert!(
            text.contains(r#""load":{"kind":"static","interp":null,"needed":[],"pie":false,"hermetic":true,"says":"This program starts itself and names no other file."}"#),
            "{text}"
        );
        assert_eq!(text.matches('{').count(), 2, "{text}");
    }
}
