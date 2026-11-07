/*
---
why: This file writes one TIFF file as one text page.
uses: bininfo
how: bininfo calls this file after it reads the IFD tags.
This file prints the profile and the photo fields.
This file does not read TIFF bytes.
---
*/

//! One page for one TIFF file.
//! Each line is `key: value  # note`. This file does not read TIFF bytes.

use super::{compression_name, Ifd, Image, Profile};
use crate::style::{self, Json};
use std::fmt::Write;

pub fn render(file: &str, image: &Image, color: bool) -> String {
    let mut out = String::new();
    crate::formats::chrome::head(
        &mut out,
        color,
        file,
        image.profile.name(),
        format_note(image.profile),
    );
    type_rung(&mut out, image, color);
    style::blank(&mut out);
    image_rung(&mut out, image, color);
    style::blank(&mut out);
    where_rung(&mut out, image, color);
    style::blank(&mut out);
    ifds_rung(&mut out, image, color);
    out
}

pub fn render_json(file: &str, image: &Image) -> String {
    let mut out = Json::new();
    crate::formats::chrome::json_head(&mut out, file, image.profile.name());
    out.str("order", image.order.name());
    out.opt("make", image.make.as_deref());
    out.opt("model", image.model.as_deref());
    opt_u64(&mut out, "orientation", image.orientation);
    opt_u64(&mut out, "iso", image.iso);
    out.opt("exposure", image.exposure.as_deref());
    out.opt("fnumber", image.fnumber.as_deref());
    out.opt("lens", image.lens.as_deref());
    out.opt("datetime", image.datetime.as_deref());
    out.opt("dng_version", image.dng_version.as_deref());
    match image.compression {
        Some(value) => {
            out.opt("compression", compression_name(value));
            out.u64("compression_id", u64::from(value));
        }
        None => out.raw("compression", "null"),
    }
    opt_u64(&mut out, "width", image.width);
    opt_u64(&mut out, "height", image.height);
    opt_u64(&mut out, "bits", image.bits);
    out.u64("ifd0", image.ifd0);
    opt_u64(&mut out, "strip", image.strip);
    opt_u64(&mut out, "jpeg", image.jpeg);
    out.flag("more", image.more);
    let rows: Vec<String> = image.ifds.iter().map(ifd_json).collect();
    out.raw_array("ifds", &rows);
    out.finish()
}

fn type_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(
        out,
        color,
        "type",
        "Byte order, make, photo fields, and compression.",
        style::GREEN,
        true,
    );
    style::field(
        out,
        color,
        2,
        "profile",
        image.profile.name(),
        "Profile name of this TIFF file.",
        style::FG,
        true,
    );
    style::field(
        out,
        color,
        2,
        "order",
        image.order.name(),
        "Byte order of each multi-byte number.",
        match image.order {
            super::Order::Little => style::BLUE,
            super::Order::Big => style::TEAL,
        },
        false,
    );
    text_field(out, color, "make", image.make.as_deref(), "Camera make.");
    text_field(out, color, "model", image.model.as_deref(), "Camera model.");
    number_field(
        out,
        color,
        "orientation",
        image.orientation,
        "Orientation of the photo.",
    );
    number_field(out, color, "iso", image.iso, "ISO of the photo.");
    text_field(
        out,
        color,
        "exposure",
        image.exposure.as_deref(),
        "Exposure time as a fraction.",
    );
    text_field(
        out,
        color,
        "fnumber",
        image.fnumber.as_deref(),
        "F number as a fraction.",
    );
    text_field(out, color, "lens", image.lens.as_deref(), "Lens name.");
    text_field(
        out,
        color,
        "datetime",
        image.datetime.as_deref(),
        "Date and time of the photo.",
    );
    text_field(
        out,
        color,
        "dng_version",
        image.dng_version.as_deref(),
        "DNG version tag 50706.",
    );
    let compression = match image.compression {
        Some(value) => style::named(compression_name(value), u64::from(value)),
        None => "null".to_string(),
    };
    style::field(
        out,
        color,
        2,
        "compression",
        &compression,
        "Compression of the chosen frame.",
        style::FG,
        false,
    );
    if image.more {
        style::field(
            out,
            color,
            2,
            "more",
            "true",
            "The IFD walk stopped at the cap.",
            style::PINK,
            false,
        );
    }
}

fn image_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(
        out,
        color,
        "image",
        "Width and height of the chosen frame.",
        style::FG,
        true,
    );
    number_field(
        out,
        color,
        "width",
        image.width,
        "Width of the chosen frame.",
    );
    number_field(
        out,
        color,
        "height",
        image.height,
        "Height of the chosen frame.",
    );
    number_field(out, color, "bits", image.bits, "Bits of the first sample.");
}

fn where_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(
        out,
        color,
        "where",
        "Offsets of the first IFD, the strip, and the preview.",
        style::BLUE,
        true,
    );
    style::field(
        out,
        color,
        2,
        "ifd0",
        &image.ifd0.to_string(),
        "Offset of the first IFD.",
        style::FG,
        false,
    );
    number_field(
        out,
        color,
        "strip",
        image.strip,
        "Offset of the first strip.",
    );
    number_field(
        out,
        color,
        "jpeg",
        image.jpeg,
        "Offset of the preview JPEG.",
    );
}

fn ifds_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(out, color, "ifds", "One row is one IFD.", style::FG, true);
    for ifd in &image.ifds {
        write_ifd(out, ifd, color);
    }
}

fn write_ifd(out: &mut String, ifd: &Ifd, color: bool) {
    let body = format!("offset: {}", ifd.offset);
    let shown = style::paint(color, &body, style::FG, false);
    let dash = style::paint(color, "-", style::LABEL, false);
    let _ = writeln!(out, "  {dash} {shown}");
    style::field(
        out,
        color,
        4,
        "entries",
        &ifd.entries.to_string(),
        "Tag count in this IFD.",
        style::FG,
        false,
    );
    style::field(
        out,
        color,
        4,
        "next",
        &ifd.next.to_string(),
        "Offset of the next IFD. 0 means none.",
        style::FG,
        false,
    );
    style::field(
        out,
        color,
        4,
        "role",
        ifd.role,
        "ifd or subifd.",
        style::FG,
        false,
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
    let (text, fg, bold) = text_or_null(value);
    style::field(out, color, 2, key, text, note, fg, bold);
}

fn text_or_null(value: Option<&str>) -> (&str, style::Rgb, bool) {
    match value {
        Some(text) => (text, style::WHITE, false),
        None => ("null", style::LABEL, false),
    }
}

fn format_note(profile: Profile) -> &'static str {
    match profile {
        Profile::Arw => "Sony ARW. This TIFF file has no start claim.",
        Profile::Dng => "DNG raw. This TIFF file has no start claim.",
        Profile::Cr2 => "Canon CR2. This TIFF file has no start claim.",
        Profile::Nef => "Nikon NEF. This TIFF file has no start claim.",
        Profile::Orf => "Olympus ORF. This TIFF file has no start claim.",
        Profile::Rw2 => "Panasonic RW2. This TIFF file has no start claim.",
        Profile::Pef => "Pentax PEF. This TIFF file has no start claim.",
        Profile::Tiff => "A TIFF file has no start claim.",
    }
}

fn ifd_json(ifd: &Ifd) -> String {
    let mut out = Json::new();
    out.u64("offset", ifd.offset);
    out.u64("entries", ifd.entries);
    out.u64("next", ifd.next);
    out.str("role", ifd.role);
    out.finish_inline()
}

fn opt_u64(out: &mut Json, key: &str, value: Option<u64>) {
    match value {
        Some(number) => out.u64(key, number),
        None => out.raw(key, "null"),
    }
}
