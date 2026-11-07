/*
---
why: This file holds one file found inside a zip member or an OCI blob.
uses: bininfo
how: step builds a hit when the user opens one member.
render prints that hit with the same page as a top-level file.
This file does not choose the next member.
---
*/

//! One nested file. The page is the same page as a top-level file.

use super::File;

pub enum Hit {
    Elf {
        header: crate::elf::header::Header,
        load: crate::elf::load::Load,
        symbols: crate::elf::symbols::Symbols,
    },
    Macho {
        image: crate::macho::header::Image,
        commands: crate::macho::load::Commands,
        slices: Vec<crate::macho::load::Slice>,
    },
    Pe {
        header: crate::pe::header::Header,
        load: crate::pe::load::Load,
        symbols: crate::pe::symbols::Symbols,
    },
    File(Box<File>),
}

pub fn render(path: &str, hit: &Hit, json: bool, color: bool) -> String {
    match hit {
        Hit::Elf {
            header,
            load,
            symbols,
        } => {
            if json {
                crate::elf::json::render_with(path, header, load, symbols)
            } else {
                crate::elf::page::render_with(path, header, load, symbols, color)
            }
        }
        Hit::Macho {
            image,
            commands,
            slices,
        } => {
            if json {
                crate::macho::json::render(path, image, commands, slices)
            } else {
                crate::macho::page::render(path, image, commands, slices, color)
            }
        }
        Hit::Pe {
            header,
            load,
            symbols,
        } => {
            if json {
                crate::pe::json::render_with(path, header, load, symbols)
            } else {
                crate::pe::page::render_with(path, header, load, symbols, color)
            }
        }
        Hit::File(file) => super::render(path, file, json, color),
    }
}
