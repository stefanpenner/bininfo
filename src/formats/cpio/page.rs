/*
---
why: This file writes one cpio archive as one text page.
uses: bininfo
how: bininfo calls this file after it reads the cpio headers.
This file does not read cpio bytes.
---
*/

//! One page for one cpio archive.
//! Each line is `key: value  # note`. This file does not read cpio bytes.

use super::{Archive, Member};
use crate::style::{self, Json};
use std::fmt::Write;

pub fn render(file: &str, archive: &Archive, color: bool) -> String {
    let mut out = String::new();
    crate::formats::chrome::head(
        &mut out,
        color,
        file,
        "cpio",
        "A cpio archive has no start claim.",
    );
    style::field(
        &mut out,
        color,
        0,
        "profile",
        archive.profile,
        "newc, crc, or odc.",
        style::FG,
        true,
    );
    style::field(
        &mut out,
        color,
        0,
        "more",
        bool_word(archive.more),
        "True when the member list reaches the cap.",
        style::FG,
        false,
    );
    style::blank(&mut out);
    members_rung(&mut out, archive, color);
    out
}

pub fn render_json(file: &str, archive: &Archive) -> String {
    let mut out = Json::new();
    out.str("file", file);
    out.str("format", "cpio");
    out.str("profile", archive.profile);
    out.flag("more", archive.more);
    let rows: Vec<String> = archive.members.iter().map(member_json).collect();
    out.raw_array("members", &rows);
    out.finish()
}

fn members_rung(out: &mut String, archive: &Archive, color: bool) {
    style::rung(
        out,
        color,
        "members",
        "One row is one cpio member.",
        style::FG,
        true,
    );
    if archive.members.is_empty() {
        style::field(
            out,
            color,
            2,
            "rows",
            "[]",
            "No member in this archive.",
            style::LABEL,
            false,
        );
        return;
    }
    for member in &archive.members {
        write_member(out, archive.profile, member, color);
    }
}

fn write_member(out: &mut String, profile: &str, member: &Member, color: bool) {
    let shown = style::file_text(color, &member.name);
    let dash = style::paint(color, "-", style::LABEL, false);
    let _ = writeln!(out, "  {dash} {shown}");
    let (fg, bold) = style::number_tone(member.size, style::FG, false);
    style::field(
        out,
        color,
        4,
        "size",
        &member.size.to_string(),
        "Byte length of the member body.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        4,
        "mode",
        &mode_line(profile, &member.mode),
        "Mode digits from the header.",
        style::FG,
        false,
    );
}

fn member_json(member: &Member) -> String {
    let mut out = Json::new();
    out.str("name", &member.name);
    out.u64("size", member.size);
    out.str("mode", &member.mode);
    out.finish_inline()
}

fn mode_line(profile: &str, mode: &str) -> String {
    let radix = if profile == "odc" { 8 } else { 16 };
    match u32::from_str_radix(mode, radix).ok().and_then(kind_word) {
        Some(kind) => format!("{mode} {kind}"),
        None => mode.to_string(),
    }
}

fn kind_word(mode: u32) -> Option<&'static str> {
    match mode & 0o170000 {
        0o100000 => Some("file"),
        0o040000 => Some("dir"),
        0o120000 => Some("symlink"),
        _ => None,
    }
}

fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
