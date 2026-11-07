/*
---
why: This file writes one OCI image as one text page.
uses: bininfo
how: bininfo calls this file after it reads the image layout.
This file does not read tar bytes.
---
*/

//! One page for one OCI image layout.
//! Each line is `key: value  # note`. This file does not read tar bytes.

use super::{Descriptor, Image, Layer, SideFile};
use crate::formats::chrome;
use crate::style::{self, Json};
use std::fmt::Write;

const NOTE: &str = "An OCI image layout has no start claim.";

pub fn render(
    file: &str,
    image: &Image,
    color: bool,
    walk_more: bool,
    layers: &[Option<String>],
    files: &[Option<String>],
) -> String {
    let mut out = String::new();
    chrome::head(&mut out, color, file, "oci", NOTE);
    type_rung(&mut out, image, color, walk_more);
    style::blank(&mut out);
    image_rung(&mut out, image, color);
    style::blank(&mut out);
    manifests_rung(&mut out, image, color);
    style::blank(&mut out);
    layers_rung(&mut out, image, color, layers);
    if !image.files.is_empty() {
        style::blank(&mut out);
        files_rung(&mut out, image, color, files);
    }
    out
}

pub fn render_json(
    file: &str,
    image: &Image,
    walk_more: bool,
    layers: &[Option<String>],
    files: &[Option<String>],
) -> String {
    let mut out = Json::new();
    chrome::json_head(&mut out, file, "oci");
    out.str("layout", &image.layout);
    opt_u64(&mut out, "schema", image.schema);
    out.opt("media_type", image.media_type.as_deref());
    out.opt("architecture", image.architecture.as_deref());
    out.opt("os", image.os.as_deref());
    out.opt("workdir", image.workdir.as_deref());
    out.strings("entrypoint", &image.entrypoint);
    out.strings("cmd", &image.cmd);
    out.strings("env", &image.env);
    out.flag("more", image.more || walk_more);
    let manifests: Vec<String> = image.manifests.iter().map(manifest_json).collect();
    out.raw_array("manifests", &manifests);
    let layer_rows: Vec<String> = image
        .layers
        .iter()
        .enumerate()
        .map(|(index, layer)| layer_json(layer, layers.get(index).and_then(|row| row.as_deref())))
        .collect();
    out.raw_array("layers", &layer_rows);
    let file_rows: Vec<String> = image
        .files
        .iter()
        .enumerate()
        .map(|(index, side)| side_json(side, files.get(index).and_then(|row| row.as_deref())))
        .collect();
    out.raw_array("files", &file_rows);
    out.finish()
}

fn type_rung(out: &mut String, image: &Image, color: bool, walk_more: bool) {
    style::rung(
        out,
        color,
        "type",
        "Layout version and index media type.",
        style::GREEN,
        true,
    );
    style::field(
        out,
        color,
        2,
        "layout",
        &image.layout,
        "imageLayoutVersion from oci-layout.",
        style::FG,
        true,
    );
    let schema = match image.schema {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    };
    style::field(
        out,
        color,
        2,
        "schema",
        &schema,
        "schemaVersion from index.json.",
        style::FG,
        false,
    );
    style::field(
        out,
        color,
        2,
        "media",
        image.media_type.as_deref().unwrap_or("null"),
        "Media type of index.json.",
        style::FG,
        false,
    );
    if image.more || walk_more {
        style::field(
            out,
            color,
            2,
            "more",
            "true",
            "The list stopped at the cap.",
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
        "Config blob of the first manifest.",
        style::TEAL,
        true,
    );
    text_field(
        out,
        color,
        2,
        "architecture",
        image.architecture.as_deref(),
        "CPU name from the config blob.",
    );
    text_field(
        out,
        color,
        2,
        "os",
        image.os.as_deref(),
        "Operating system from the config blob.",
    );
    text_field(
        out,
        color,
        2,
        "workdir",
        image.workdir.as_deref(),
        "WorkingDir from the image config.",
    );
    style::list_field(
        out,
        color,
        2,
        "entrypoint",
        &image.entrypoint,
        "Entrypoint from the image config.",
        style::FG,
        false,
    );
    style::list_field(
        out,
        color,
        2,
        "cmd",
        &image.cmd,
        "Cmd from the image config.",
        style::FG,
        false,
    );
    style::list_field(
        out,
        color,
        2,
        "env",
        &image.env,
        "Env from the image config. The list stops at 16 rows.",
        style::FG,
        false,
    );
}

fn manifests_rung(out: &mut String, image: &Image, color: bool) {
    style::rung(
        out,
        color,
        "manifests",
        "One row is one manifest descriptor.",
        style::FG,
        true,
    );
    if image.manifests.is_empty() {
        style::field(
            out,
            color,
            2,
            "rows",
            "[]",
            "No manifest in the kept rows.",
            style::LABEL,
            false,
        );
        return;
    }
    for manifest in &image.manifests {
        write_manifest(out, manifest, color);
    }
}

fn write_manifest(out: &mut String, manifest: &Descriptor, color: bool) {
    let name = manifest.digest.as_deref().unwrap_or("manifest");
    let shown = style::file_text(color, name);
    let dash = style::paint(color, "-", style::LABEL, false);
    let _ = writeln!(out, "  {dash} {shown}");
    text_field(
        out,
        color,
        4,
        "media",
        manifest.media_type.as_deref(),
        "Media type of this manifest.",
    );
    let size = match manifest.size {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    };
    style::field(
        out,
        color,
        4,
        "size",
        &size,
        "Declared byte length of the manifest blob.",
        style::FG,
        false,
    );
    text_field(
        out,
        color,
        4,
        "platform",
        manifest.platform.as_deref(),
        "OS and architecture from the descriptor.",
    );
}

fn layers_rung(out: &mut String, image: &Image, color: bool, layers: &[Option<String>]) {
    style::rung(
        out,
        color,
        "layers",
        "One row is one layer descriptor.",
        style::BLUE,
        true,
    );
    if image.layers.is_empty() {
        style::field(
            out,
            color,
            2,
            "rows",
            "[]",
            "No layer in the kept rows.",
            style::LABEL,
            false,
        );
        return;
    }
    for (index, layer) in image.layers.iter().enumerate() {
        write_layer(out, layer, color);
        if let Some(Some(text)) = layers.get(index) {
            out.push_str(&chrome::nest(text));
        }
    }
}

fn write_layer(out: &mut String, layer: &Layer, color: bool) {
    let name = layer.digest.as_deref().unwrap_or("layer");
    let shown = style::file_text(color, name);
    let dash = style::paint(color, "-", style::LABEL, false);
    let _ = writeln!(out, "  {dash} {shown}");
    text_field(
        out,
        color,
        4,
        "media",
        layer.media_type.as_deref(),
        "Media type of this layer.",
    );
    let size = match layer.size {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    };
    style::field(
        out,
        color,
        4,
        "size",
        &size,
        "Declared byte length of this layer.",
        style::FG,
        false,
    );
}

fn files_rung(out: &mut String, image: &Image, color: bool, files: &[Option<String>]) {
    style::rung(
        out,
        color,
        "files",
        "Enter opens one side file.",
        style::FG,
        true,
    );
    for (index, side) in image.files.iter().enumerate() {
        let shown = style::file_text(color, &side.name);
        let dash = style::paint(color, "-", style::LABEL, false);
        let _ = writeln!(out, "  {dash} {shown}");
        if let Some(Some(text)) = files.get(index) {
            out.push_str(&chrome::nest(text));
        }
    }
}

fn text_field(
    out: &mut String,
    color: bool,
    indent: usize,
    key: &str,
    value: Option<&str>,
    note: &str,
) {
    style::field(
        out,
        color,
        indent,
        key,
        value.unwrap_or("null"),
        note,
        style::FG,
        false,
    );
}

fn manifest_json(manifest: &Descriptor) -> String {
    let mut out = Json::new();
    out.opt("media_type", manifest.media_type.as_deref());
    out.opt("digest", manifest.digest.as_deref());
    opt_u64(&mut out, "size", manifest.size);
    out.opt("platform", manifest.platform.as_deref());
    out.finish_inline()
}

fn layer_json(layer: &Layer, inner: Option<&str>) -> String {
    let mut out = Json::new();
    out.opt("media_type", layer.media_type.as_deref());
    out.opt("digest", layer.digest.as_deref());
    opt_u64(&mut out, "size", layer.size);
    match inner.map(str::trim_end) {
        Some(json) => out.raw("inner", json),
        None => out.raw("inner", "null"),
    }
    out.finish_inline()
}

fn side_json(side: &SideFile, inner: Option<&str>) -> String {
    let mut out = Json::new();
    out.str("name", &side.name);
    match inner.map(str::trim_end) {
        Some(json) => out.raw("inner", json),
        None => out.raw("inner", "null"),
    }
    out.finish_inline()
}

fn opt_u64(out: &mut Json, key: &str, value: Option<u64>) {
    match value {
        Some(number) => out.u64(key, number),
        None => out.raw(key, "null"),
    }
}
