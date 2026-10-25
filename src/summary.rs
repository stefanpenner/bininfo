/*
---
why: This file adds the file size, the regions, and the certs to a page.
uses: bininfo
how: The bininfo command reads the file bytes once.
This file turns those bytes into text lines and JSON keys.
The page text from each format stays as it is.
---
*/

//! File size, regions, and embedded certs for the default page.
//! Text sizes are human. JSON sizes are bytes.

use crate::certs::{self, Hit, Region, Role};
use crate::style;
use crate::trust::{self, Bads, Verdict};
use std::fmt::Write;

const REGION_ROWS: usize = 64;
const CERT_ROWS: usize = 200;
const SIGNER_NAMES: usize = 8;

pub struct Summary {
    pub size: u64,
    pub regions: Vec<Region>,
    pub certs: Certs,
}

/// The scanned certs and a verdict for each. `loaded` is false until the scan runs.
#[derive(Default)]
pub struct Certs {
    pub loaded: bool,
    pub hits: Vec<Hit>,
    pub verdicts: Vec<Verdict>,
    pub bads: Bads,
}

/// Size and regions only. They are cheap. The certs stay unloaded.
pub fn read_cheap(bytes: &[u8]) -> Summary {
    Summary {
        size: bytes.len() as u64,
        regions: certs::regions(bytes),
        certs: Certs::default(),
    }
}

/// Everything. `online` lets the bad list refresh from the network.
pub fn read(bytes: &[u8], online: bool) -> Summary {
    Summary {
        certs: scan_certs(bytes, online),
        ..read_cheap(bytes)
    }
}

/// The slow part: scan for certs and judge each one.
pub fn scan_certs(bytes: &[u8], online: bool) -> Certs {
    let hits = certs::scan(bytes);
    let bads = trust::load(online);
    let now = trust::now();
    let verdicts = hits
        .iter()
        .map(|hit| trust::judge(hit, &bads, now))
        .collect();
    Certs {
        loaded: true,
        hits,
        verdicts,
        bads,
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn json_str(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn word<T: std::fmt::Debug>(value: T) -> String {
    format!("{value:?}").to_lowercase()
}

/// One hit as a JSON object. `by` says why a match request kept it.
pub fn hit_json(hit: &Hit, by: Option<&str>, verdict: Option<&Verdict>) -> String {
    let secs = |v: Option<i64>| v.map_or("null".into(), |n| n.to_string());
    let (valid, reason) = match verdict {
        Some(Verdict::Valid) => ("true".to_string(), "null".to_string()),
        Some(Verdict::Invalid(why)) => ("false".to_string(), json_str(why)),
        _ => ("null".to_string(), "null".to_string()),
    };
    format!(
        "{{\"offset\":{},\"length\":{},\"kind\":\"{}\",\"role\":\"{}\",\"container\":\"{}\",\"place\":{},\"sha256\":\"{}\",\"spki_sha256\":\"{}\",\"subject_cn\":{},\"not_before\":{},\"not_after\":{},\"valid\":{},\"reason\":{},\"matched_by\":{}}}",
        hit.offset,
        hit.length,
        word(hit.kind),
        word(hit.role),
        word(hit.container),
        json_str(&hit.place),
        hex(&hit.sha256),
        hex(&hit.spki_sha256),
        hit.subject_cn.as_deref().map_or("null".into(), json_str),
        secs(hit.not_before),
        secs(hit.not_after),
        valid,
        reason,
        by.map_or("null".into(), |b| format!("\"{b}\"")),
    )
}

/// The `size:` line. It goes under `format:`.
pub fn size_line(summary: &Summary, color: bool) -> String {
    let mut out = String::new();
    style::field(
        &mut out,
        color,
        0,
        "size",
        &style::human(summary.size),
        "Size of this file.",
        style::WHITE,
        false,
    );
    out
}

/// The `regions:` and `certs:` rungs. They go at the end of the page.
pub fn tail(summary: &Summary, color: bool) -> String {
    let mut out = String::new();
    regions_rung(&mut out, summary, color);
    certs_rung(&mut out, summary, color);
    out
}

fn regions_rung(out: &mut String, summary: &Summary, color: bool) {
    if summary.regions.is_empty() {
        return;
    }
    style::blank(out);
    style::rung(
        out,
        color,
        "regions",
        "Segments and sections by file offset, with the bytes each one holds.",
        style::FG,
        true,
    );
    for region in summary.regions.iter().take(REGION_ROWS) {
        let kind = if region.section { "section" } else { "segment" };
        let note = format!("{kind} at {}", style::hex(region.offset as u64));
        let line = format!("{}: {}", region.name, style::human(region.size as u64));
        let _ = write_item(out, color, 2, &line, &note);
    }
    if summary.regions.len() > REGION_ROWS {
        let more = summary.regions.len() - REGION_ROWS;
        style::field(
            out,
            color,
            2,
            "more",
            &more.to_string(),
            "Regions not shown.",
            style::LABEL,
            false,
        );
    }
}

fn certs_rung(out: &mut String, summary: &Summary, color: bool) {
    if !summary.certs.loaded {
        style::blank(out);
        style::rung(
            out,
            color,
            "certs",
            "Not loaded. Press enter to scan. Run --certs to scan without the TUI.",
            style::FG,
            true,
        );
        return;
    }
    let judged: Vec<(&Hit, &Verdict)> = summary
        .certs
        .hits
        .iter()
        .zip(&summary.certs.verdicts)
        .collect();
    let trust: Vec<(&Hit, &Verdict)> = judged
        .iter()
        .filter(|(h, _)| h.role == Role::Trust)
        .copied()
        .collect();
    let signer: Vec<&Hit> = judged
        .iter()
        .filter(|(h, _)| h.role == Role::Signer)
        .map(|(h, _)| *h)
        .collect();
    let bad = trust
        .iter()
        .filter(|(_, v)| matches!(v, Verdict::Invalid(_)))
        .count();
    style::blank(out);
    style::rung(
        out,
        color,
        "certs",
        "Embedded certificates. Trust certs are listed. Signer certs are counted. Run --certs for every row.",
        style::FG,
        true,
    );
    style::field(
        out,
        color,
        2,
        "trust",
        &trust.len().to_string(),
        "Certs and anchors the program may trust.",
        style::WHITE,
        false,
    );
    style::field(
        out,
        color,
        2,
        "signer",
        &signer.len().to_string(),
        "Certs from the code signature.",
        style::WHITE,
        false,
    );
    let mut names: Vec<String> = signer.iter().filter_map(|h| h.subject_cn.clone()).collect();
    names.sort();
    names.dedup();
    names.truncate(SIGNER_NAMES);
    if !names.is_empty() {
        style::list_field(
            out,
            color,
            2,
            "signer_cns",
            &names,
            "Subjects of the signer certs.",
            style::WHITE,
            false,
        );
    }
    style::field(
        out,
        color,
        2,
        "invalid",
        &bad.to_string(),
        &format!("Trust certs that are expired or on a bad list. Bad list: {}.", summary.certs.bads.source),
        if bad > 0 { style::RED } else { style::WHITE },
        bad > 0,
    );
    if !trust.is_empty() {
        style::field(
            out,
            color,
            2,
            "list",
            "",
            "Trust certs, in file order.",
            style::LABEL,
            false,
        );
    }
    for (hit, verdict) in trust.iter().take(CERT_ROWS) {
        let cn = hit.subject_cn.as_deref().unwrap_or("null");
        let mut note = format!(
            "{} {} in {}, {}",
            word(hit.kind),
            word(hit.encoding),
            hit.place,
            style::human(hit.length as u64)
        );
        let (mark, fg) = match verdict {
            Verdict::Valid => (verdict.mark(), style::GREEN),
            Verdict::Unknown => (verdict.mark(), style::LABEL),
            Verdict::Invalid(why) => {
                note = format!("{why}; {note}");
                (verdict.mark(), style::RED)
            }
        };
        let tag = style::paint(color, mark, fg, true);
        let _ = write_item(out, color, 4, &format!("{tag} cn: {cn}"), &note);
        let _ = writeln!(out, "      sha256: {}", hex(&hit.sha256));
        let _ = writeln!(out, "      spki_sha256: {}", hex(&hit.spki_sha256));
    }
    if trust.len() > CERT_ROWS {
        style::field(
            out,
            color,
            2,
            "more",
            &(trust.len() - CERT_ROWS).to_string(),
            "Trust certs not shown.",
            style::LABEL,
            false,
        );
    }
}

fn write_item(
    out: &mut String,
    color: bool,
    indent: usize,
    text: &str,
    note: &str,
) -> std::fmt::Result {
    let plain = indent + 2 + plain_len(text);
    let dash = style::paint(color, "-", style::LABEL, false);
    style::align_note(
        out,
        color,
        &format!("{}{dash} {text}", " ".repeat(indent)),
        plain,
        note,
    );
    Ok(())
}

/// The keys to add to a JSON page: size and regions in bytes, and every cert hit.
pub fn json_keys(summary: &Summary) -> String {
    let regions: Vec<String> = summary
        .regions
        .iter()
        .map(|r| {
            format!(
                "{{\"kind\":\"{}\",\"name\":{},\"offset\":{},\"size\":{}}}",
                if r.section { "section" } else { "segment" },
                json_str(&r.name),
                r.offset,
                r.size
            )
        })
        .collect();
    let hits: Vec<String> = summary
        .certs
        .hits
        .iter()
        .zip(&summary.certs.verdicts)
        .map(|(h, v)| hit_json(h, None, Some(v)))
        .collect();
    format!(
        ",\"size\":{},\"regions\":[{}],\"certs\":[{}]",
        summary.size,
        regions.join(","),
        hits.join(",")
    )
}

fn plain_len(text: &str) -> usize {
    plain(text).chars().count()
}

fn plain(line: &str) -> String {
    let mut out = String::new();
    let mut skip = false;
    for c in line.chars() {
        match (skip, c) {
            (_, '\u{1b}') => skip = true,
            (true, 'm') => skip = false,
            (false, c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// Put the summary into a rendered page. Text gets `size:` under `format:` and the rungs at the end.
/// JSON gets the keys before the closing brace.
pub fn merge(page: &str, summary: &Summary, json: bool, color: bool) -> String {
    if json {
        return match page.trim_end().strip_suffix('}') {
            Some(body) => format!("{body}{}}}\n", json_keys(summary)),
            None => page.to_string(),
        };
    }
    let mut out = String::new();
    let mut put = false;
    for line in page.split_inclusive('\n') {
        out.push_str(line);
        if !put && plain(line).starts_with("format:") {
            out.push_str(&size_line(summary, color));
            put = true;
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&tail(summary, color));
    out
}
