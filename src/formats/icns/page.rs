/*
---
why: This file writes one Apple icon set as one text page.
uses: bininfo
how: bininfo calls this file after the icns parse.
This file lists one row for each icon.
This file does not read icon bytes.
---
*/

//! One page for one Apple icon set.
//! Each line is `key: value  # note`. This file does not read icon bytes.

use super::{Icon, Image};
use crate::formats::chrome;
use crate::style::{self, Json};
use std::fmt::Write;

const FORMAT_NOTE: &str = "An Apple icon file has no start claim.";

pub fn render(file: &str, image: &Image, color: bool) -> String {
    let mut out = String::new();
    chrome::head(&mut out, color, file, "icns", FORMAT_NOTE);
    style::field(
        &mut out,
        color,
        0,
        "bytes",
        &image.bytes.to_string(),
        "Byte length from the icns header.",
        style::FG,
        false,
    );
    if image.more {
        style::field(
            &mut out,
            color,
            0,
            "more",
            "true",
            "The icon list stopped at the cap.",
            style::PINK,
            false,
        );
    }
    style::blank(&mut out);
    icons_rung(&mut out, image, color);
    out
}

pub fn render_json(file: &str, image: &Image) -> String {
    let mut out = Json::new();
    chrome::json_head(&mut out, file, "icns");
    out.u64("bytes", image.bytes);
    out.flag("more", image.more);
    let rows: Vec<String> = image.icons.iter().map(icon_json).collect();
    out.raw_array("icons", &rows);
    out.finish()
}

fn icons_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(
        out,
        color,
        "icons",
        "Enter opens one icon.",
        style::FG,
        true,
    );
    if image.icons.is_empty() {
        style::field(
            out,
            color,
            2,
            "rows",
            "[]",
            "No icon in this file.",
            style::LABEL,
            false,
        );
        return;
    }
    for icon in &image.icons {
        write_icon(out, icon, color);
    }
}

fn write_icon(out: &mut String, icon: &Icon, color: bool) {
    let shown = style::file_text(color, &icon.kind);
    let dash = style::paint(color, "-", style::LABEL, false);
    let _ = writeln!(out, "  {dash} {shown}");
    let (fg, bold) = style::number_tone(icon.size, style::FG, false);
    style::field(
        out,
        color,
        4,
        "size",
        &icon.size.to_string(),
        "Byte size of this icon.",
        fg,
        bold,
    );
    style::field(
        out,
        color,
        4,
        "encoding",
        icon.encoding,
        "png, jpeg, jpeg2000, rgb, mask, or other.",
        style::FG,
        false,
    );
    if let Some(pixels) = icon.pixels {
        let (fg, bold) = style::number_tone(pixels, style::FG, false);
        style::field(
            out,
            color,
            4,
            "pixels",
            &pixels.to_string(),
            "Nominal side length of this icon type.",
            fg,
            bold,
        );
    }
}

fn icon_json(icon: &Icon) -> String {
    let mut out = Json::new();
    out.str("kind", &icon.kind);
    out.u64("size", icon.size);
    out.str("encoding", icon.encoding);
    if let Some(pixels) = icon.pixels {
        out.u64("pixels", pixels);
    }
    out.finish_inline()
}
