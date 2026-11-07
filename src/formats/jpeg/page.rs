/*
---
why: This file writes one JPEG file as one text page.
uses: bininfo
how: bininfo calls this file after the JPEG parse.
This file writes the frame header and the short APP facts.
This file does not read JPEG bytes.
---
*/

//! One page for one JPEG file.
//! Each line is `key: value  # note`. This file does not read JPEG bytes.

use super::Image;
use crate::formats::chrome;
use crate::style::{self, Json};

const FORMAT_NOTE: &str = "A JPEG file has no start claim.";

pub fn render(file: &str, image: &Image, color: bool) -> String {
    let mut out = String::new();
    chrome::head(&mut out, color, file, "jpeg", FORMAT_NOTE);
    frame_rung(&mut out, image, color);
    out
}

pub fn render_json(file: &str, image: &Image) -> String {
    let mut out = Json::new();
    chrome::json_head(&mut out, file, "jpeg");
    opt_u64(&mut out, "width", image.width);
    opt_u64(&mut out, "height", image.height);
    opt_u64(&mut out, "bits", image.bits);
    opt_u64(&mut out, "components", image.components);
    out.opt("frame", image.frame);
    out.opt("jfif", image.jfif.as_deref());
    out.opt("density", image.density.as_deref());
    out.flag("exif", image.exif);
    opt_u8(&mut out, "adobe", image.adobe);
    out.finish()
}

fn frame_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(
        out,
        color,
        "frame",
        "Frame header and short APP facts.",
        style::GREEN,
        true,
    );
    number_field(out, color, "width", image.width, "Width of the frame.");
    number_field(out, color, "height", image.height, "Height of the frame.");
    number_field(out, color, "bits", image.bits, "Sample precision.");
    number_field(
        out,
        color,
        "components",
        image.components,
        "Count of frame components.",
    );
    text_field(out, color, "frame", image.frame, "Frame type.");
    let ids = id_list(&image.component_ids);
    let ids_fg = if image.component_ids.is_empty() {
        style::LABEL
    } else {
        style::FG
    };
    style::field(
        out,
        color,
        2,
        "ids",
        &ids,
        "Component ids from the frame.",
        ids_fg,
        false,
    );
    text_field(
        out,
        color,
        "jfif",
        image.jfif.as_deref(),
        "JFIF version from APP0.",
    );
    text_field(
        out,
        color,
        "density",
        image.density.as_deref(),
        "JFIF density from APP0.",
    );
    style::field(
        out,
        color,
        2,
        "exif",
        bool_word(image.exif),
        "True for an Exif prefix.",
        if image.exif {
            style::PINK
        } else {
            style::LABEL
        },
        false,
    );
    let adobe = match image.adobe {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    };
    let (adobe_fg, adobe_bold) = match image.adobe {
        Some(value) => style::number_tone(u64::from(value), style::FG, false),
        None => (style::LABEL, false),
    };
    style::field(
        out,
        color,
        2,
        "adobe",
        &adobe,
        "Transform byte from APP14.",
        adobe_fg,
        adobe_bold,
    );
}

fn number_field(out: &mut String, color: bool, key: &str, value: Option<u64>, note: &str) {
    let text = match value {
        Some(number) => number.to_string(),
        None => "null".to_string(),
    };
    let (fg, bold) = match value {
        Some(number) => style::number_tone(number, style::FG, false),
        None => (style::LABEL, false),
    };
    style::field(out, color, 2, key, &text, note, fg, bold);
}

fn text_field(out: &mut String, color: bool, key: &str, value: Option<&str>, note: &str) {
    let (text, fg, bold) = match value {
        Some(text) => (text, style::FG, false),
        None => ("null", style::LABEL, false),
    };
    style::field(out, color, 2, key, text, note, fg, bold);
}

fn id_list(ids: &[u8]) -> String {
    if ids.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::new();
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&style::hex(u64::from(*id)));
    }
    out
}

fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn opt_u64(out: &mut Json, key: &str, value: Option<u64>) {
    match value {
        Some(number) => out.u64(key, number),
        None => out.raw(key, "null"),
    }
}

fn opt_u8(out: &mut Json, key: &str, value: Option<u8>) {
    match value {
        Some(number) => out.u64(key, u64::from(number)),
        None => out.raw(key, "null"),
    }
}
