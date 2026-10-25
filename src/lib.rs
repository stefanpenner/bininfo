/*
---
why: This file is the library a caller uses.
uses: bininfo
how: The bininfo command calls open, render, and facts.
A caller uses certs to scan file bytes.
---
*/

//! Read one ELF, Mach-O, or PE file.
//! `open` reads the bytes. `render` prints the page. `facts` feeds a claim.
//! `elf`, `macho`, and `pe` read one format each.
//! `certs` finds embedded certificates in file bytes.

pub mod certs;
pub mod claim;
pub mod elf;
pub mod kind;
pub mod macho;
pub mod pe;
pub mod summary;

mod library;
mod style;

use std::process::Command;

/// One parsed ELF, Mach-O, or PE file.
pub enum Binary {
    Elf {
        header: elf::header::Header,
        load: elf::load::Load,
        symbols: elf::symbols::Symbols,
    },
    Macho {
        image: macho::header::Image,
        commands: macho::load::Commands,
        slices: Vec<macho::load::Slice>,
    },
    Pe {
        header: pe::header::Header,
        load: pe::load::Load,
        symbols: pe::symbols::Symbols,
    },
}

/// Read one file. `rows` keeps symbol rows.
pub fn open(bytes: &[u8], rows: bool) -> Result<Binary, String> {
    if elf::header::is_elf(bytes) {
        let header = elf::header::parse(bytes)?;
        let load = elf::load::read(bytes, &header);
        let symbols = elf::symbols::read(bytes, &header, rows);
        return Ok(Binary::Elf {
            header,
            load,
            symbols,
        });
    }
    if macho::header::is_macho(bytes) {
        let image = macho::header::parse(bytes)?;
        let slices = macho::load::slices_rows(bytes, &image, rows);
        let commands = match &image {
            macho::header::Image::Fat(_) => macho::load::commands_for(&slices),
            macho::header::Image::Thin(_) => macho::load::read_at(bytes, &image, rows),
        };
        return Ok(Binary::Macho {
            image,
            commands,
            slices,
        });
    }
    if pe::header::is_pe(bytes) {
        let header = pe::header::parse(bytes)?;
        let load = pe::load::read(bytes, &header);
        let symbols = pe::symbols::read(bytes, &header, rows);
        return Ok(Binary::Pe {
            header,
            load,
            symbols,
        });
    }
    Err("not an ELF, Mach-O, or PE file".into())
}

/// Print one page, or one JSON object when `json` is true.
pub fn render(path: &str, file: &Binary, json: bool, color: bool) -> String {
    match file {
        Binary::Elf {
            header,
            load,
            symbols,
        } => {
            if json {
                elf::json::render_with(path, header, load, symbols)
            } else {
                elf::page::render_with(path, header, load, symbols, color)
            }
        }
        Binary::Macho {
            image,
            commands,
            slices,
        } => {
            if json {
                macho::json::render(path, image, commands, slices)
            } else {
                macho::page::render(path, image, commands, slices, color)
            }
        }
        Binary::Pe {
            header,
            load,
            symbols,
        } => {
            if json {
                pe::json::render_with(path, header, load, symbols)
            } else {
                pe::page::render_with(path, header, load, symbols, color)
            }
        }
    }
}

/// Build the facts a claim checks. `host` does not change the hermetic result.
pub fn facts(path: &str, file: &Binary, host: &claim::Host) -> claim::Facts {
    match file {
        Binary::Elf {
            header,
            load,
            symbols,
        } => claim::Facts {
            file: path.to_string(),
            format: "elf",
            kind: load.kind,
            interp: load.interp.clone(),
            needed: load.needed.clone(),
            pie: load.pie,
            fat_hermetic: None,
            host: claim::host_marks(&elf::symbols::floors(header, symbols), host),
        },
        Binary::Macho {
            image,
            commands,
            slices,
        } => claim::Facts {
            file: path.to_string(),
            format: "macho",
            kind: commands.load.kind,
            interp: commands.load.interp.clone(),
            needed: commands.load.names(),
            pie: commands.load.pie,
            fat_hermetic: macho::load::fat_hermetic(slices),
            host: claim::host_marks(&macho::symbols::floors(image, commands, slices), host),
        },
        Binary::Pe {
            header,
            load,
            symbols,
        } => claim::Facts {
            file: path.to_string(),
            format: "pe",
            kind: load.kind,
            interp: load.interp.clone(),
            needed: load.needed.clone(),
            pie: load.pie,
            fat_hermetic: None,
            host: claim::host_marks(&pe::symbols::floors(header, symbols), host),
        },
    }
}

/// Scan `bytes` for embedded certificates and trust anchors.
/// The scan reads DER, PEM, bare base64, gzip, zlib, and zip.
pub fn certs(bytes: &[u8]) -> Vec<certs::Hit> {
    certs::scan(bytes)
}

/// Read the CPU and OS of this machine.
pub fn current_host() -> claim::Host {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let version = match os {
        "macos" => command_version("sw_vers", &["-productVersion"]),
        "linux" => command_version("uname", &["-r"]),
        _ => None,
    };
    claim::Host {
        arch,
        os,
        version,
        pac: os == "macos" && arch == "aarch64",
    }
}

fn command_version(bin: &str, args: &[&str]) -> Option<claim::Version> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    claim::parse_version(text.trim())
}
