/*
---
why: This file writes one PNG file as one text page.
uses: bininfo
how: bininfo calls this file after the PNG parse.
This file writes the IHDR fields.
This file does not read PNG bytes.
---
*/

//! One page for one PNG file.
//! Each line is `key: value  # note`. This file does not read PNG bytes.

use super::Image;
use crate::formats::chrome;
use crate::style::{self, Json};

const FORMAT_NOTE: &str = "A PNG file has no start claim.";

pub fn render(file: &str, image: &Image, color: bool) -> String {
    let mut out = String::new();
    chrome::head(&mut out, color, file, "png", FORMAT_NOTE);
    frame_rung(&mut out, image, color);
    out
}

pub fn render_json(file: &str, image: &Image) -> String {
    let mut out = Json::new();
    chrome::json_head(&mut out, file, "png");
    out.u64("width", image.width);
    out.u64("height", image.height);
    out.u64("depth", image.depth);
    out.str("color", image.color);
    out.finish()
}

fn frame_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(
        out,
        color,
        "frame",
        "IHDR width, height, depth, and color.",
        style::GREEN,
        true,
    );
    number(out, color, "width", image.width, "Width in pixels.");
    number(out, color, "height", image.height, "Height in pixels.");
    number(out, color, "depth", image.depth, "Bit depth of one sample.");
    style::field(
        out,
        color,
        2,
        "color",
        image.color,
        "gray, rgb, palette, gray-alpha, or rgba.",
        style::FG,
        false,
    );
}

fn number(out: &mut String, color: bool, key: &str, value: u64, note: &str) {
    let (fg, bold) = style::number_tone(value, style::FG, false);
    style::field(out, color, 2, key, &value.to_string(), note, fg, bold);
}
