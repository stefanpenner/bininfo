/*
---
why: This file writes one 7z archive as one text page.
uses: bininfo
how: bininfo calls this file after it reads the signature header.
This file does not read 7z bytes.
This file does not decode LZMA.
---
*/

//! One page for one 7z archive.
//! Each line is `key: value  # note`. This file does not read 7z bytes.
//! This file does not decode LZMA.

use super::Archive;
use crate::style::{self, Json};

const FORMAT_NOTE: &str = "A 7z archive has no start claim. The header is encoded.";

pub fn render(file: &str, archive: &Archive, color: bool) -> String {
    let mut out = String::new();
    crate::formats::chrome::head(&mut out, color, file, "7z", FORMAT_NOTE);
    let version = format!("{}.{}", archive.major, archive.minor);
    style::field(
        &mut out,
        color,
        0,
        "version",
        &version,
        "Archive major and minor.",
        style::FG,
        false,
    );
    let (fg, bold) = style::number_tone(archive.header_offset, style::FG, false);
    style::field(
        &mut out,
        color,
        0,
        "header_offset",
        &archive.header_offset.to_string(),
        "Byte offset of the next header.",
        fg,
        bold,
    );
    let (fg, bold) = style::number_tone(archive.header_size, style::FG, false);
    style::field(
        &mut out,
        color,
        0,
        "header_size",
        &archive.header_size.to_string(),
        "Byte length of the next header. The CRC is stored and not checked.",
        fg,
        bold,
    );
    style::field(
        &mut out,
        color,
        0,
        "encoded",
        bool_word(archive.encoded),
        "The next header is encoded.",
        style::FG,
        archive.encoded,
    );
    out
}

pub fn render_json(file: &str, archive: &Archive) -> String {
    let mut out = Json::new();
    crate::formats::chrome::json_head(&mut out, file, "7z");
    out.u64("major", u64::from(archive.major));
    out.u64("minor", u64::from(archive.minor));
    out.u64("header_offset", archive.header_offset);
    out.u64("header_size", archive.header_size);
    out.u64("header_crc", u64::from(archive.header_crc));
    out.flag("encoded", archive.encoded);
    out.finish()
}

fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
