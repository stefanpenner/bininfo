/*
---
why: This file writes one tar archive as one text page.
uses: bininfo
how: bininfo calls this file after it reads the headers.
This file does not read tar bytes.
---
*/

//! One page for one tar archive.
//! Each line is `key: value  # note`. This file does not read tar bytes.

use super::{Archive, Member};
use crate::formats::chrome;
use crate::style::{self, Json};
use std::fmt::Write;

pub fn render(file: &str, archive: &Archive, color: bool) -> String {
    let mut out = String::new();
    chrome::head(
        &mut out,
        color,
        file,
        "tar",
        "A tar archive has no start claim.",
    );
    members_rung(&mut out, archive, color);
    out
}

pub fn render_json(file: &str, archive: &Archive) -> String {
    let mut out = Json::new();
    chrome::json_head(&mut out, file, "tar");
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
        "One row is one ustar header.",
        style::FG,
        true,
    );
    if archive.more {
        style::field(
            out,
            color,
            2,
            "more",
            "true",
            "The member walk stopped at the cap.",
            style::PINK,
            false,
        );
    }
    if archive.members.is_empty() {
        style::field(
            out,
            color,
            2,
            "rows",
            "[]",
            "No member in the kept rows.",
            style::LABEL,
            false,
        );
        return;
    }
    for member in &archive.members {
        write_member(out, member, color);
    }
}

fn write_member(out: &mut String, member: &Member, color: bool) {
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
        "Byte length of this member.",
        fg,
        bold,
    );
    let (fg, bold) = kind_color(member.kind);
    style::field(
        out,
        color,
        4,
        "kind",
        member.kind,
        "Type of this member.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        4,
        "mode",
        &member.mode,
        "Permission bits in octal.",
        style::FG,
        false,
    );
}

fn member_json(member: &Member) -> String {
    let mut out = Json::new();
    out.str("name", &member.name);
    out.u64("size", member.size);
    out.str("kind", member.kind);
    out.str("mode", &member.mode);
    out.finish_inline()
}

fn kind_color(kind: &str) -> (style::Rgb, bool) {
    match kind {
        "file" => (style::FG, true),
        "dir" => (style::GREEN, true),
        "symlink" => (style::MAGENTA, true),
        "link" => (style::BLUE, true),
        "pax" => (style::TEAL, false),
        "other" => (style::PINK, false),
        _ => (style::AMBER, false),
    }
}
