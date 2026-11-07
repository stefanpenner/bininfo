/*
---
why: This file writes one Wasm module as one text page.
uses: bininfo
how: bininfo calls this file after the module read.
This file does not read Wasm bytes.
The page states that a Wasm module has no start claim.
---
*/

//! One page for one Wasm module.
//! Each line is `key: value  # note`. This file does not read Wasm bytes.

use super::Module;
use crate::formats::chrome;
use crate::style::{self, Json};

const NOTE: &str = "A Wasm module has no start claim.";

pub fn render(file: &str, module: &Module, color: bool) -> String {
    let mut out = String::new();
    chrome::head(&mut out, color, file, "wasm", NOTE);
    let version = u64::from(module.version);
    let (fg, bold) = style::number_tone(version, style::FG, false);
    style::field(
        &mut out,
        color,
        0,
        "version",
        &version.to_string(),
        "Binary version.",
        fg,
        bold,
    );
    let sections: Vec<String> = module
        .sections
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    style::list_field(
        &mut out,
        color,
        0,
        "sections",
        &sections,
        "Section names in file order.",
        style::FG,
        false,
    );
    write_imports(&mut out, module, color);
    write_exports(&mut out, module, color);
    let (min, max) = match module.memory {
        Some((min, max)) => (Some(min), max),
        None => (None, None),
    };
    number_or_null(
        &mut out,
        color,
        "memory_min",
        min,
        "Minimum memory in pages.",
    );
    number_or_null(
        &mut out,
        color,
        "memory_max",
        max,
        "Maximum memory in pages.",
    );
    number_or_null(
        &mut out,
        color,
        "start",
        module.start,
        "Start section index. This is not a start claim.",
    );
    style::field(
        &mut out,
        color,
        0,
        "more",
        if module.more { "true" } else { "false" },
        "True when a cap or an extra memory drops a row.",
        if module.more {
            style::PINK
        } else {
            style::LABEL
        },
        false,
    );
    out
}

pub fn render_json(file: &str, module: &Module) -> String {
    let mut out = Json::new();
    chrome::json_head(&mut out, file, "wasm");
    out.u64("version", u64::from(module.version));
    let sections: Vec<String> = module
        .sections
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    out.strings("sections", &sections);
    let imports: Vec<String> = module.imports.iter().map(import_json).collect();
    out.raw_array("imports", &imports);
    let exports: Vec<String> = module.exports.iter().map(export_json).collect();
    out.raw_array("exports", &exports);
    let (min, max) = match module.memory {
        Some((min, max)) => (Some(min), max),
        None => (None, None),
    };
    opt_u64(&mut out, "memory_min", min);
    opt_u64(&mut out, "memory_max", max);
    opt_u64(&mut out, "start", module.start);
    out.flag("more", module.more);
    out.finish()
}

fn write_imports(out: &mut String, module: &Module, color: bool) {
    if module.imports.is_empty() {
        style::field(
            out,
            color,
            0,
            "imports",
            "[]",
            "No import.",
            style::LABEL,
            false,
        );
        return;
    }
    for row in &module.imports {
        let shown = format!("{}.{}", row.module, row.name);
        style::field(out, color, 0, "import", &shown, row.kind, style::FG, false);
    }
}

fn write_exports(out: &mut String, module: &Module, color: bool) {
    if module.exports.is_empty() {
        style::field(
            out,
            color,
            0,
            "exports",
            "[]",
            "No export.",
            style::LABEL,
            false,
        );
        return;
    }
    for row in &module.exports {
        let note = format!("{} index {}", row.kind, row.index);
        style::field(out, color, 0, "export", &row.name, &note, style::FG, false);
    }
}

fn number_or_null(out: &mut String, color: bool, key: &str, value: Option<u64>, note: &str) {
    match value {
        Some(number) => {
            let (fg, bold) = style::number_tone(number, style::FG, false);
            style::field(out, color, 0, key, &number.to_string(), note, fg, bold);
        }
        None => style::field(out, color, 0, key, "null", note, style::LABEL, false),
    }
}

fn import_json(row: &super::Import) -> String {
    let mut out = Json::new();
    out.str("module", &row.module);
    out.str("name", &row.name);
    out.str("kind", row.kind);
    out.finish_inline()
}

fn export_json(row: &super::Export) -> String {
    let mut out = Json::new();
    out.str("name", &row.name);
    out.str("kind", row.kind);
    out.u64("index", row.index);
    out.finish_inline()
}

fn opt_u64(out: &mut Json, key: &str, value: Option<u64>) {
    match value {
        Some(number) => out.u64(key, number),
        None => out.raw(key, "null"),
    }
}
