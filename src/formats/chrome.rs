/*
---
why: This file writes the shared head of one format page.
uses: bininfo
how: Each format page calls head for the file line and the format line.
Each format page calls json_head for the same two keys.
nest indents one inner page.
This file does not read file bytes.
---
*/

//! Shared file line and format line. A format page adds only its own fields.

use crate::style::{self, Json};

/// Write the file line and the format line, then one blank line.
pub fn head(out: &mut String, color: bool, file: &str, format: &str, note: &str) {
    style::field(
        out,
        color,
        0,
        "file",
        file,
        "Path of this file.",
        style::WHITE,
        false,
    );
    style::field(out, color, 0, "format", format, note, style::FG, true);
    style::blank(out);
}

/// Write the file key and the format key.
pub fn json_head(out: &mut Json, file: &str, format: &str) {
    out.str("file", file);
    out.str("format", format);
}

/// Indent one finished page by four spaces.
pub fn nest(page: &str) -> String {
    let mut out = String::new();
    for line in page.split_inclusive('\n') {
        out.push_str("    ");
        out.push_str(line);
        if !line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}
