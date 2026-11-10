/*
---
why: This file reads one named member inside another file.
uses: bininfo
how: bininfo calls step when the user opens one member.
step sniffs that member and stops when asked.
The next name opens one file inside that member.
An inflate stops at 1 MiB.
A watch stops that read.
---
*/

//! One step reads one named member.
//! The next name opens one file inside that member.
//! A 7z archive and an MPQ archive do not open a member.

use super::File;
use crate::Watch;
use std::borrow::Cow;

const INFLATE_CAP: usize = 1 << 20;
const INPUT_CAP: usize = 8 << 20;
const CHAIN_CAP: usize = 32;

enum Take<'a> {
    Body(Cow<'a, [u8]>),
    Cap,
}

/// Read the one file named by `path`.
/// Each name is one member of the file named before it.
/// The page lists the next names and does not read them.
pub fn step(bytes: &[u8], path: &[&str], rows: bool, color: bool, watch: &Watch) -> Option<String> {
    if watch.stopped() || path.is_empty() || path.len() > CHAIN_CAP {
        return None;
    }
    let file = super::sniff(bytes)?.ok()?;
    follow(bytes, &file, path, rows, color, watch)
}

fn follow(
    bytes: &[u8],
    file: &File,
    path: &[&str],
    rows: bool,
    color: bool,
    watch: &Watch,
) -> Option<String> {
    if watch.stopped() {
        return None;
    }
    if let File::Dmg(image) = file {
        return open_dmg(bytes, image, path, rows, color, watch);
    }
    let (name, rest) = path.split_first()?;
    match one(bytes, file, name)? {
        Take::Cap => Some(cap_page(name)),
        Take::Body(body) if rest.is_empty() => page_of(&body, name, rows, color),
        Take::Body(body) => next_file(&body, rest, rows, color, watch),
    }
}

fn next_file(
    bytes: &[u8],
    path: &[&str],
    rows: bool,
    color: bool,
    watch: &Watch,
) -> Option<String> {
    if crate::elf::header::is_elf(bytes)
        || crate::macho::header::is_macho(bytes)
        || crate::pe::header::is_pe(bytes)
    {
        return None;
    }
    if watch.stopped() {
        return None;
    }
    let file = super::sniff(bytes)?.ok()?;
    follow(bytes, &file, path, rows, color, watch)
}

fn page_of(bytes: &[u8], name: &str, rows: bool, color: bool) -> Option<String> {
    if crate::elf::header::is_elf(bytes)
        || crate::macho::header::is_macho(bytes)
        || crate::pe::header::is_pe(bytes)
    {
        let hit = start_hit(bytes, rows)?;
        return Some(super::hit::render(name, &hit, false, color));
    }
    let file = super::sniff(bytes)?.ok()?;
    Some(super::render(name, &file, false, color))
}

fn open_dmg(
    bytes: &[u8],
    image: &super::dmg::Image,
    path: &[&str],
    rows: bool,
    color: bool,
    watch: &Watch,
) -> Option<String> {
    let (name, rest) = path.split_first()?;
    let part = image.parts.iter().find(|part| part.name == *name)?;
    if rest.is_empty() {
        return step_of(
            super::dmg::view_part(bytes, part, color, watch),
            name,
            &[],
            rows,
            color,
            watch,
        );
    }
    let (file_name, deeper) = rest.split_first()?;
    match super::dmg::view_file(bytes, part, file_name, watch) {
        super::dmg::Step::Stop => None,
        super::dmg::Step::Body(body) => step_of(
            super::dmg::Step::Body(body),
            file_name,
            deeper,
            rows,
            color,
            watch,
        ),
        super::dmg::Step::Cap => {
            step_of(super::dmg::Step::Cap, file_name, deeper, rows, color, watch)
        }
        super::dmg::Step::Miss | super::dmg::Step::Page(_) => step_of(
            super::dmg::view_part(bytes, part, color, watch),
            name,
            rest,
            rows,
            color,
            watch,
        ),
    }
}

fn step_of(
    step: super::dmg::Step,
    name: &str,
    rest: &[&str],
    rows: bool,
    color: bool,
    watch: &Watch,
) -> Option<String> {
    match step {
        super::dmg::Step::Page(text) if rest.is_empty() => Some(text),
        super::dmg::Step::Cap => Some(cap_page(name)),
        super::dmg::Step::Body(body) if rest.is_empty() => page_of(&body, name, rows, color),
        super::dmg::Step::Body(body) => next_file(&body, rest, rows, color, watch),
        _ => None,
    }
}

fn one<'a>(bytes: &'a [u8], file: &File, name: &str) -> Option<Take<'a>> {
    match file {
        File::Zip(archive) => {
            let member = archive.members.iter().find(|member| member.name == name)?;
            zip_body(bytes, member)
        }
        File::Tar(archive) => {
            let member = archive.members.iter().find(|member| member.name == name)?;
            let body = super::tar::body(bytes, member)?;
            borrowed(body)
        }
        File::Ar(archive) => {
            let member = archive.members.iter().find(|member| member.name == name)?;
            let body = slice_at(bytes, member.offset, member.size)?;
            borrowed(body)
        }
        File::Cpio(archive) => {
            let member = archive.members.iter().find(|member| member.name == name)?;
            let body = slice_at(bytes, member.offset, member.size)?;
            borrowed(body)
        }
        File::Icns(image) => {
            let icon = image.icons.iter().find(|icon| icon.kind == name)?;
            let body = slice_at(bytes, icon.offset, icon.size)?;
            borrowed(body)
        }
        File::Oci(image) => {
            if let Some(layer) = image
                .layers
                .iter()
                .find(|layer| layer.digest.as_deref() == Some(name))
            {
                return layer_body(bytes, layer);
            }
            let side = image.files.iter().find(|side| side.name == name)?;
            slice_at(bytes, side.offset, side.stored).map(|body| Take::Body(Cow::Borrowed(body)))
        }
        _ => None,
    }
}

fn zip_body<'a>(bytes: &'a [u8], member: &super::zip::Member) -> Option<Take<'a>> {
    if member.encrypted {
        return None;
    }
    if member.method == 0 {
        return super::zip::stored(bytes, member).map(|body| Take::Body(Cow::Borrowed(body)));
    }
    if member.method != 8 {
        return None;
    }
    if member.size > INFLATE_CAP as u64 || member.compressed > INPUT_CAP as u64 {
        return Some(Take::Cap);
    }
    let raw = super::zip::deflated(bytes, member)?;
    crate::certs::inflate_deflate(raw, INFLATE_CAP).map(|body| Take::Body(Cow::Owned(body)))
}

fn layer_body<'a>(bytes: &'a [u8], layer: &super::oci::Layer) -> Option<Take<'a>> {
    let offset = layer.offset?;
    let stored = layer.stored?;
    let body = slice_at(bytes, offset, stored)?;
    if body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b {
        if body.len() > INPUT_CAP {
            return Some(Take::Cap);
        }
        return crate::certs::inflate_gzip(body, INFLATE_CAP)
            .map(|out| Take::Body(Cow::Owned(out)));
    }
    Some(Take::Body(Cow::Borrowed(body)))
}

fn borrowed(body: &[u8]) -> Option<Take<'_>> {
    if body.is_empty() {
        return None;
    }
    Some(Take::Body(Cow::Borrowed(body)))
}

fn slice_at(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let at = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    let end = at.checked_add(len)?;
    bytes.get(at..end)
}

fn start_hit(bytes: &[u8], rows: bool) -> Option<super::hit::Hit> {
    if crate::elf::header::is_elf(bytes) {
        let header = crate::elf::header::parse(bytes).ok()?;
        let load = crate::elf::load::read(bytes, &header);
        let symbols = crate::elf::symbols::read(bytes, &header, rows);
        return Some(super::hit::Hit::Elf {
            header,
            load,
            symbols,
        });
    }
    if crate::macho::header::is_macho(bytes) {
        let image = crate::macho::header::parse(bytes).ok()?;
        let slices = crate::macho::load::slices_rows(bytes, &image, rows);
        let commands = match &image {
            crate::macho::header::Image::Fat(_) => crate::macho::load::commands_for(&slices),
            crate::macho::header::Image::Thin(_) => {
                crate::macho::load::read_at(bytes, &image, rows)
            }
        };
        return Some(super::hit::Hit::Macho {
            image,
            commands,
            slices,
        });
    }
    if crate::pe::header::is_pe(bytes) {
        let header = crate::pe::header::parse(bytes).ok()?;
        let load = crate::pe::load::read(bytes, &header);
        let symbols = crate::pe::symbols::read(bytes, &header, rows);
        return Some(super::hit::Hit::Pe {
            header,
            load,
            symbols,
        });
    }
    None
}

fn cap_page(name: &str) -> String {
    let label = if name.chars().any(|c| c == '\n' || c == '\r') {
        "member"
    } else {
        name
    };
    format!("file: {label}\nreason: This file is past the 1 MiB inflate cap.\n")
}
