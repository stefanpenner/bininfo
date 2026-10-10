//! Words for Mach-O numbers. This file does not read Mach-O bytes.

use super::header::{Class, Data, Fat, FileType};

pub(crate) fn class_name(class: Class) -> &'static str {
    match class {
        Class::Mach32 => "MH32",
        Class::Mach64 => "MH64",
        Class::Fat => "FAT",
        Class::Fat64 => "FAT64",
    }
}

pub(crate) fn data_name(data: Data) -> &'static str {
    match data {
        Data::Little => "little-endian",
        Data::Big => "big-endian",
    }
}

pub(crate) fn cpu_name(cputype: u32) -> Option<&'static str> {
    match cputype {
        7 => Some("x86"),
        0x0100_0007 => Some("x86-64"),
        12 => Some("ARM"),
        0x0100_000c => Some("AArch64"),
        18 => Some("PowerPC"),
        0x0100_0012 => Some("PowerPC64"),
        _ => None,
    }
}

pub(crate) fn slice_labels(fat: &Fat) -> Vec<String> {
    fat.arches
        .iter()
        .map(|arch| {
            let cpu = cpu_name(arch.cputype).unwrap_or("cpu");
            format!("{cpu} {:#x} {}", arch.offset, arch.size)
        })
        .collect()
}

pub(crate) fn file_name(kind: FileType) -> String {
    match kind {
        FileType::Object => "OBJECT".into(),
        FileType::Execute => "EXECUTE".into(),
        FileType::FvmLib => "FVMLIB".into(),
        FileType::Core => "CORE".into(),
        FileType::Preload => "PRELOAD".into(),
        FileType::Dylib => "DYLIB".into(),
        FileType::Dylinker => "DYLINKER".into(),
        FileType::Bundle => "BUNDLE".into(),
        FileType::Other(n) => n.to_string(),
    }
}
