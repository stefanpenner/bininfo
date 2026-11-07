/*
---
why: This file writes one ar archive as one text page.
uses: bininfo
how: bininfo calls this file after it reads the member headers.
This file does not read ar bytes.
---
*/

//! One page for one ar archive.
//! Each line is `key: value  # note`.
//! This file does not read ar bytes.

use super::{Archive, Member};
use crate::style::{self, Json};
use std::fmt::Write;

const FORMAT_NOTE: &str = "An ar archive has no start claim.";

pub fn render(file: &str, archive: &Archive, color: bool) -> String {
    let mut out = String::new();
    crate::formats::chrome::head(&mut out, color, file, "ar", FORMAT_NOTE);
    members_rung(&mut out, archive, color);
    out
}

pub fn render_json(file: &str, archive: &Archive) -> String {
    let mut out = Json::new();
    crate::formats::chrome::json_head(&mut out, file, "ar");
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
        "One row is one archive member.",
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
    } else {
        for member in &archive.members {
            write_member(out, member, color);
        }
    }
    if archive.more {
        style::field(
            out,
            color,
            2,
            "more",
            "true",
            "The member list hit the cap.",
            style::PINK,
            false,
        );
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
        "Byte size of this member.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        4,
        "mode",
        &member.mode,
        "Mode text of this member.",
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
