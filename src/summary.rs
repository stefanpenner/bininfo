/*
---
why: This file adds the file size, the regions, the signature, and the certs to a page.
uses: bininfo
how: The bininfo command reads the file bytes once.
This file turns those bytes into text lines and JSON keys.
The page text from each format stays as it is.
A section line sits under its segment.
The sign rung says whether a signature is valid.
---
*/

//! File size, regions, the signature, and embedded certs for the default page.
//! Text sizes are human. JSON sizes are bytes.

use crate::certs::{self, Hit, Region, Role};
use crate::sign::{self, Sign};
use crate::style;
use crate::trust::{self, Bads, Verdict};
use std::fmt::Write;

const REGION_ROWS: usize = 64;
const CERT_ROWS: usize = 200;
const SIGNER_NAMES: usize = 8;

pub struct Summary {
    pub size: u64,
    pub regions: Vec<Region>,
    pub sign: Sign,
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
        sign: sign::read(bytes),
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
    let valid = match verdict {
        Some(Verdict::Valid) => "true",
        Some(Verdict::Unknown) | None => "null",
        Some(_) => "false",
    };
    let status = verdict.map_or("null".into(), |v| format!("\"{}\"", v.status()));
    let reason = verdict
        .and_then(Verdict::reason)
        .map_or("null".into(), |r| json_str(&r));
    let url = verdict
        .and_then(Verdict::url)
        .map_or("null".into(), json_str);
    format!(
        "{{\"offset\":{},\"length\":{},\"kind\":\"{}\",\"role\":\"{}\",\"container\":\"{}\",\"place\":{},\"sha256\":\"{}\",\"spki_sha256\":\"{}\",\"subject_cn\":{},\"not_before\":{},\"not_after\":{},\"valid\":{},\"status\":{},\"reason\":{},\"url\":{},\"matched_by\":{}}}",
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
        status,
        reason,
        url,
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
    sign_rung(&mut out, summary, color);
    regions_rung(&mut out, summary, color);
    certs_rung(&mut out, summary, color);
    out
}

fn sign_rung(out: &mut String, summary: &Summary, color: bool) {
    style::blank(out);
    style::rung(
        out,
        color,
        "sign",
        "A signature check. Absent means this file has no signature record.",
        style::FG,
        true,
    );
    let (fg, bold) = match summary.sign.status {
        "valid" => (style::GREEN, true),
        "invalid" => (style::RED, true),
        _ => (style::LABEL, false),
    };
    style::field(
        out,
        color,
        2,
        "status",
        summary.sign.status,
        &summary.sign.reason,
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "kind",
        summary.sign.kind,
        kind_note(summary.sign.kind),
        if summary.sign.kind == "none" {
            style::LABEL
        } else {
            style::WHITE
        },
        false,
    );
    style::field(
        out,
        color,
        2,
        "reason",
        &summary.sign.reason,
        "Why the status has this value.",
        fg,
        false,
    );
}

fn kind_note(kind: &str) -> &'static str {
    match kind {
        "macho" => "[LC_CODE_SIGNATURE] Mach-O code signature.",
        "pe" => "[IMAGE_DIRECTORY_ENTRY_SECURITY] Authenticode certificate table.",
        _ => "This file has no signature record.",
    }
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
        "A segment lists each section it holds. The size is the bytes in that range.",
        style::FG,
        true,
    );
    let owners = owners_of(&summary.regions);
    let mut used = vec![false; summary.regions.len()];
    let mut shown = 0usize;
    for index in 0..summary.regions.len() {
        if used[index] || shown >= REGION_ROWS {
            continue;
        }
        let region = &summary.regions[index];
        if region.section && owners[index].is_some() {
            continue;
        }
        write_region(out, color, 2, region);
        used[index] = true;
        shown += 1;
        if region.section {
            continue;
        }
        for child in 0..summary.regions.len() {
            if shown >= REGION_ROWS || used[child] || owners[child] != Some(index) {
                continue;
            }
            write_region(out, color, 4, &summary.regions[child]);
            used[child] = true;
            shown += 1;
        }
    }
    if shown < summary.regions.len() {
        let more = summary.regions.len() - shown;
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
    let count = |want: &str| trust.iter().filter(|(_, v)| v.status() == want).count();
    let (critical, expired, not_yet, distrusted, revoked) = (
        count("critical"),
        count("expired"),
        count("not_yet_valid"),
        count("distrusted"),
        count("revoked"),
    );
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
        "critical",
        &critical.to_string(),
        "Compromised or leaked keys, such as the eMudhra advisory CAs. Broken. Act first.",
        if critical > 0 {
            style::CRITICAL
        } else {
            style::WHITE
        },
        critical > 0,
    );
    style::field(
        out,
        color,
        2,
        "distrusted",
        &distrusted.to_string(),
        &format!(
            "Distrusted or removed from a root store. Bad list: {}.",
            summary.certs.bads.source
        ),
        if distrusted > 0 {
            style::RED
        } else {
            style::WHITE
        },
        distrusted > 0,
    );
    style::field(
        out,
        color,
        2,
        "revoked",
        &revoked.to_string(),
        "Revoked by the CA, per the CCADB list.",
        if revoked > 0 {
            style::RED
        } else {
            style::WHITE
        },
        revoked > 0,
    );
    style::field(
        out,
        color,
        2,
        "expired",
        &expired.to_string(),
        "Past the notAfter date.",
        if expired > 0 {
            style::AMBER
        } else {
            style::WHITE
        },
        expired > 0,
    );
    if not_yet > 0 {
        style::field(
            out,
            color,
            2,
            "not_yet_valid",
            &not_yet.to_string(),
            "Before the notBefore date.",
            style::AMBER,
            true,
        );
    }
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
        let fg = match verdict {
            Verdict::Valid => style::GREEN,
            Verdict::Unknown => style::LABEL,
            Verdict::Expired(_) | Verdict::NotYetValid(_) => style::AMBER,
            Verdict::Distrusted { kind, .. } if kind == "critical" => style::CRITICAL,
            Verdict::Distrusted { .. } => style::RED,
        };
        let mark = verdict.mark();
        if let Some(why) = verdict.reason() {
            note = format!("{why}; {note}");
        }
        let tag = style::paint(color, mark, fg, true);
        let _ = write_item(out, color, 4, &format!("{tag} cn: {cn}"), &note);
        if let Some(url) = verdict.url() {
            let _ = writeln!(out, "      read: {url}");
        }
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

// A Mach-O zerofill section keeps file offset 0 and names its segment.
fn owners_of(regions: &[Region]) -> Vec<Option<usize>> {
    regions
        .iter()
        .map(|region| {
            if region.section {
                owner_of(regions, region)
            } else {
                None
            }
        })
        .collect()
}

fn owner_of(regions: &[Region], child: &Region) -> Option<usize> {
    let end = child.offset.saturating_add(child.size);
    let mut best: Option<(usize, usize)> = None;
    for (index, seg) in regions.iter().enumerate() {
        if seg.section {
            continue;
        }
        if let Some(name) = child.parent.as_deref() {
            if seg.name != name {
                continue;
            }
        }
        let seg_end = seg.offset.saturating_add(seg.size);
        if child.offset < seg.offset || end > seg_end {
            continue;
        }
        let tighter = best.map(|(_, size)| seg.size < size).unwrap_or(true);
        if tighter {
            best = Some((index, seg.size));
        }
    }
    if let Some((index, _)) = best {
        return Some(index);
    }
    if child.offset == 0 {
        let name = child.parent.as_deref()?;
        return regions
            .iter()
            .position(|seg| !seg.section && seg.name == name);
    }
    None
}

fn write_region(out: &mut String, color: bool, indent: usize, region: &Region) {
    let kind = if region.section { "section" } else { "segment" };
    let note = format!("{kind} at {}", style::hex(region.offset as u64));
    let line = format!("{}: {}", region.name, style::human(region.size as u64));
    let _ = write_item(out, color, indent, &line, &note);
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
        ",\"sign\":{{\"status\":{},\"kind\":{},\"reason\":{}}},\"size\":{},\"regions\":[{}],\"certs\":[{}]",
        json_str(summary.sign.status),
        json_str(summary.sign.kind),
        json_str(&summary.sign.reason),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], at: usize, value: u64) {
        buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_name(buf: &mut [u8], at: usize, text: &str) {
        buf[at..at + text.len()].copy_from_slice(text.as_bytes());
    }

    fn segment(buf: &mut [u8], at: usize, name: &str, fileoff: u64, filesize: u64, nsects: u32) {
        put_u32(buf, at, 0x19);
        put_u32(buf, at + 4, 72 + 80 * nsects);
        put_name(buf, at + 8, name);
        put_u64(buf, at + 40, fileoff);
        put_u64(buf, at + 48, filesize);
        put_u32(buf, at + 64, nsects);
    }

    fn section(
        buf: &mut [u8],
        at: usize,
        sect: &str,
        seg: &str,
        size: u64,
        offset: u32,
        flags: u32,
    ) {
        put_name(buf, at, sect);
        put_name(buf, at + 16, seg);
        put_u64(buf, at + 40, size);
        put_u32(buf, at + 48, offset);
        put_u32(buf, at + 64, flags);
    }

    /// Two segments. `__const` exists in both. `__thread_bss` has file offset 0.
    fn two_segments() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        put_u32(&mut bytes, 16, 2);
        put_u32(&mut bytes, 20, 464);
        segment(&mut bytes, 32, "__TEXT", 0, 0x400, 2);
        section(&mut bytes, 104, "__text", "__TEXT", 4, 0x100, 0);
        section(&mut bytes, 184, "__const", "__TEXT", 8, 0x200, 0);
        segment(&mut bytes, 264, "__DATA", 0x300, 0x100, 2);
        section(&mut bytes, 336, "__const", "__DATA", 8, 0x300, 0);
        section(&mut bytes, 416, "__thread_bss", "__DATA", 168, 0, 0x12);
        bytes
    }

    fn region_rows(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| line.contains("segment at") || line.contains("section at"))
            .collect()
    }

    #[test]
    fn a_segment_lists_its_sections() {
        let text = tail(&read_cheap(&two_segments()), false);
        let rows = region_rows(&text);
        assert_eq!(rows.len(), 6, "{text}");
        assert!(rows[0].starts_with("  - __TEXT:"), "{text}");
        assert!(rows[1].starts_with("    - __text:"), "{text}");
        assert!(rows[2].starts_with("    - __const:"), "{text}");
        assert!(rows[2].contains("0x200"), "{text}");
        assert!(rows[3].starts_with("  - __DATA:"), "{text}");
        assert!(rows[4].starts_with("    - __thread_bss:"), "{text}");
        assert!(rows[5].starts_with("    - __const:"), "{text}");
        assert!(rows[5].contains("0x300"), "{text}");
    }

    #[test]
    fn a_real_macho_and_elf_nest_sections() {
        let macho = std::fs::read("samples/out/libtiny.dylib").unwrap();
        let text = tail(&read_cheap(&macho), false);
        assert!(text.contains("    - __text:"), "{text}");
        assert!(
            !text.lines().any(|line| line.starts_with("  - __text:")),
            "{text}"
        );

        let elf = std::fs::read("samples/out/lib-x86-64.so").unwrap();
        let text = tail(&read_cheap(&elf), false);
        let at = text.find("  - PT_LOAD: 6 B").expect(&text);
        let next = text[at..].lines().nth(1).unwrap_or("");
        assert!(next.starts_with("    - "), "{next}\n{text}");
        assert!(next.contains(".text:"), "{next}\n{text}");
    }

    #[test]
    fn a_short_macho_does_not_panic() {
        let mut bytes = vec![0u8; 32];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[16] = 40;
        bytes[20] = 255;
        let regions = std::panic::catch_unwind(|| crate::certs::regions(&bytes));
        assert!(regions.is_ok());
    }
}
