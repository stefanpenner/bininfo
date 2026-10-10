//! Page lines and JSON tokens. No file format lives here.

use crate::kind::Kind;
use std::fmt::Write;

pub const COLUMN: usize = 32;

#[derive(Clone, Copy)]
pub struct Rgb(pub u8, pub u8, pub u8);

pub const FG: Rgb = Rgb(0xf2, 0xf4, 0xf8);
pub const NOTE: Rgb = Rgb(0xb6, 0xb8, 0xbb);
pub const LABEL: Rgb = Rgb(0x7b, 0x7c, 0x7e);
pub const GREEN: Rgb = Rgb(0x25, 0xbe, 0x6a);
pub const TEAL: Rgb = Rgb(0x08, 0xbd, 0xba);
pub const BLUE: Rgb = Rgb(0x78, 0xa9, 0xff);
pub const CYAN: Rgb = Rgb(0x33, 0xb1, 0xff);
pub const MAGENTA: Rgb = Rgb(0xbe, 0x95, 0xff);
pub const PINK: Rgb = Rgb(0xff, 0x7e, 0xb6);
pub const WHITE: Rgb = Rgb(0xdf, 0xdf, 0xe0);

pub fn blank(out: &mut String) {
    out.push('\n');
}

pub fn rung(out: &mut String, color: bool, title: &str, note: &str, fg: Rgb, bold: bool) {
    let text = format!("{title}:");
    let pad = " ".repeat(COLUMN.saturating_sub(text.chars().count()));
    let title = paint(color, &text, fg, bold);
    let note = paint(color, &format!("# {note}"), NOTE, false);
    let _ = writeln!(out, "{title}{pad}  {note}");
}

pub fn field(
    out: &mut String,
    color: bool,
    indent: usize,
    key: &str,
    value: &str,
    note: &str,
    fg: Rgb,
    bold: bool,
) {
    let shown = show(value);
    raw_field(out, color, indent, key, &shown, note, fg, bold);
}

pub fn raw_field(
    out: &mut String,
    color: bool,
    indent: usize,
    key: &str,
    shown: &str,
    note: &str,
    fg: Rgb,
    bold: bool,
) {
    emit(
        out,
        color,
        indent,
        key,
        shown,
        shown.chars().count(),
        note,
        fg,
        bold,
    );
}

pub fn yaml_list(names: &[String]) -> String {
    if names.is_empty() {
        return "[]".to_string();
    }
    let items: Vec<String> = names.iter().map(|name| show(name)).collect();
    format!("[{}]", items.join(", "))
}

pub fn kind_tone(kind: Kind) -> (Rgb, bool) {
    match kind {
        Kind::Static => (GREEN, true),
        Kind::DynamicPie | Kind::StaticPie => (CYAN, true),
        Kind::Dynamic => (BLUE, true),
        Kind::Shared => (MAGENTA, true),
        Kind::Rel => (TEAL, false),
        Kind::Other => (PINK, false),
    }
}

pub fn number_tone(n: u64, fg: Rgb, bold: bool) -> (Rgb, bool) {
    if n == 0 {
        (LABEL, false)
    } else {
        (fg, bold)
    }
}

pub fn word_tone(name: Option<&str>, fg: Rgb, bold: bool) -> (Rgb, bool) {
    if name.is_none() {
        (LABEL, false)
    } else {
        (fg, bold)
    }
}

pub fn paint(on: bool, text: &str, color: Rgb, bold: bool) -> String {
    if !on {
        return text.to_string();
    }
    let Rgb(r, g, b) = color;
    if bold {
        format!("\x1b[1;38;2;{r};{g};{b}m{text}\x1b[0m")
    } else {
        format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
    }
}

fn emit(
    out: &mut String,
    color: bool,
    indent: usize,
    key: &str,
    shown: &str,
    width: usize,
    note: &str,
    fg: Rgb,
    bold: bool,
) {
    let plain = indent + key.len() + 2 + width;
    let pad = " ".repeat(COLUMN.saturating_sub(plain));
    let gap = " ".repeat(indent);
    let key = paint(color, &format!("{key}:"), LABEL, false);
    let value = paint(color, shown, fg, bold);
    let note = paint(color, &format!("# {note}"), NOTE, false);
    let _ = writeln!(out, "{gap}{key} {value}{pad}  {note}");
}

fn show(value: &str) -> String {
    if value.contains('#') || value.contains('\n') || value.contains('"') {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

/// One JSON object. The caller chooses the keys.
pub struct Json {
    out: String,
}

impl Json {
    pub fn new() -> Self {
        Self {
            out: String::from("{"),
        }
    }

    pub fn str(&mut self, key: &str, value: &str) {
        self.comma();
        self.out.push_str(&json_str(key));
        self.out.push(':');
        self.out.push_str(&json_str(value));
    }

    pub fn opt(&mut self, key: &str, value: Option<&str>) {
        self.comma();
        self.out.push_str(&json_str(key));
        self.out.push(':');
        match value {
            Some(text) => self.out.push_str(&json_str(text)),
            None => self.out.push_str("null"),
        }
    }

    pub fn u64(&mut self, key: &str, value: u64) {
        self.comma();
        self.out.push_str(&json_str(key));
        self.out.push(':');
        self.out.push_str(&value.to_string());
    }

    pub fn u8s(&mut self, key: &str, bytes: &[u8]) {
        self.comma();
        self.out.push_str(&json_str(key));
        self.out.push_str(":[");
        for (i, byte) in bytes.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            self.out.push_str(&byte.to_string());
        }
        self.out.push(']');
    }

    pub fn strings(&mut self, key: &str, values: &[String]) {
        self.comma();
        self.out.push_str(&json_str(key));
        self.out.push_str(":[");
        for (i, value) in values.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            self.out.push_str(&json_str(value));
        }
        self.out.push(']');
    }

    pub fn flag(&mut self, key: &str, value: bool) {
        self.comma();
        self.out.push_str(&json_str(key));
        self.out.push(':');
        self.out.push_str(if value { "true" } else { "false" });
    }

    pub fn pairs(&mut self, key: &str, left: &str, right: &str, rows: &[(&str, &str)]) {
        self.comma();
        self.out.push_str(&json_str(key));
        self.out.push_str(":[");
        for (index, (a, b)) in rows.iter().enumerate() {
            if index > 0 {
                self.out.push(',');
            }
            self.out.push('{');
            self.out.push_str(&json_str(left));
            self.out.push(':');
            self.out.push_str(&json_str(a));
            self.out.push(',');
            self.out.push_str(&json_str(right));
            self.out.push(':');
            self.out.push_str(&json_str(b));
            self.out.push('}');
        }
        self.out.push(']');
    }

    pub fn load(
        &mut self,
        kind: &str,
        interp: Option<&str>,
        needed: &[String],
        pie: bool,
        hermetic: bool,
        says: &str,
    ) {
        self.comma();
        self.out.push_str("\"load\":{\"kind\":");
        self.out.push_str(&json_str(kind));
        self.out.push_str(",\"interp\":");
        match interp {
            Some(path) => self.out.push_str(&json_str(path)),
            None => self.out.push_str("null"),
        }
        self.out.push_str(",\"needed\":[");
        for (index, name) in needed.iter().enumerate() {
            if index > 0 {
                self.out.push(',');
            }
            self.out.push_str(&json_str(name));
        }
        self.out.push_str("],\"pie\":");
        self.out.push_str(if pie { "true" } else { "false" });
        self.out.push_str(",\"hermetic\":");
        self.out.push_str(if hermetic { "true" } else { "false" });
        self.out.push_str(",\"says\":");
        self.out.push_str(&json_str(says));
        self.out.push('}');
    }

    pub fn finish(mut self) -> String {
        self.out.push('}');
        self.out.push('\n');
        self.out
    }

    fn comma(&mut self) {
        if self.out.len() > 1 {
            self.out.push(',');
        }
    }
}

fn json_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
