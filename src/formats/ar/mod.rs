/*
---
why: This file reads one Unix ar member list.
uses: bininfo
how: bininfo calls this file when the first bytes are the ar magic.
This file reads member headers only.
This file does not open a member.
---
*/

//! One Unix ar archive.
//! This module reads member headers.
//! This module does not open a member.

pub mod page;

const MAGIC: &[u8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;
const MEMBER_CAP: usize = 4096;
// A BSD length above this limit is an error.
// A System V name stops at this limit.
const NAME_CAP: usize = 256;
const OUTSIDE: &str = "ar member is outside this file";

/// One archive member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub size: u64,
    pub mode: String,
}

/// One ar archive.
/// `more` is true when the member list hit the cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    pub members: Vec<Member>,
    pub more: bool,
}

/// True when the first bytes are the ar magic.
pub fn is_ar(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Read each member header.
/// This function does not open a member.
pub fn parse(bytes: &[u8]) -> Result<Archive, String> {
    if !is_ar(bytes) {
        return Err("not an ar archive".into());
    }
    let mut at = MAGIC.len();
    let mut members = Vec::new();
    let mut more = false;
    let mut long_names: Option<(usize, usize)> = None;
    while at < bytes.len() {
        if members.len() == MEMBER_CAP {
            more = true;
            break;
        }
        let header = header_at(bytes, at)?;
        let stored = decimal(&header[48..58], "ar size is not decimal")?;
        let mode = text(trim_ends(&header[40..48]));
        let raw = text(trim_end(&header[0..16]));
        let body_at = at + HEADER_LEN;
        let body_end = end_at(body_at, stored, bytes.len())?;
        let (name, size) = member_name(bytes, &raw, body_at, stored, long_names)?;
        if raw == "//" {
            long_names = Some((body_at, body_end));
        }
        members.push(Member { name, size, mode });
        at = next_at(bytes, body_end);
    }
    Ok(Archive { members, more })
}

fn header_at(bytes: &[u8], at: usize) -> Result<&[u8], String> {
    let end = at
        .checked_add(HEADER_LEN)
        .ok_or("ar member header is outside this file")?;
    let header = bytes
        .get(at..end)
        .ok_or("ar member header is outside this file")?;
    if header.get(58..60) != Some(b"`\n") {
        return Err("ar member trailer is wrong".into());
    }
    Ok(header)
}

fn end_at(start: usize, len: u64, file_len: usize) -> Result<usize, String> {
    let len = usize::try_from(len).map_err(|_| OUTSIDE)?;
    let end = start.checked_add(len).ok_or(OUTSIDE)?;
    if end > file_len {
        return Err(OUTSIDE.into());
    }
    Ok(end)
}

// A later header has an even offset.
// The last member can end on an odd offset.
fn next_at(bytes: &[u8], body_end: usize) -> usize {
    if body_end % 2 == 0 || body_end == bytes.len() {
        return body_end;
    }
    body_end + 1
}

fn member_name(
    bytes: &[u8],
    raw: &str,
    body_at: usize,
    stored: u64,
    long_names: Option<(usize, usize)>,
) -> Result<(String, u64), String> {
    if let Some(len) = bsd_len(raw)? {
        return bsd_name(bytes, body_at, stored, len);
    }
    if raw == "/" || raw == "//" {
        return Ok((raw.to_string(), stored));
    }
    if let Some(offset) = sysv_at(raw)? {
        return sysv_name(bytes, raw, offset, stored, long_names);
    }
    Ok((trim_slash(raw), stored))
}

fn bsd_len(raw: &str) -> Result<Option<u64>, String> {
    let Some(rest) = raw.strip_prefix("#1/") else {
        return Ok(None);
    };
    let len = decimal(rest.as_bytes(), "ar name length is not decimal")?;
    if len > NAME_CAP as u64 {
        return Err("ar long name is too long".into());
    }
    Ok(Some(len))
}

fn bsd_name(bytes: &[u8], body_at: usize, stored: u64, len: u64) -> Result<(String, u64), String> {
    if len > stored {
        return Err(OUTSIDE.into());
    }
    let name_len = len as usize;
    let name_end = body_at.checked_add(name_len).ok_or(OUTSIDE)?;
    let raw = bytes.get(body_at..name_end).ok_or(OUTSIDE)?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    Ok((text(&raw[..end]), stored - len))
}

fn sysv_at(raw: &str) -> Result<Option<u64>, String> {
    let Some(rest) = raw.strip_prefix('/') else {
        return Ok(None);
    };
    if rest.is_empty() || rest.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Ok(None);
    }
    Ok(Some(decimal(
        rest.as_bytes(),
        "ar long name is not decimal",
    )?))
}

fn sysv_name(
    bytes: &[u8],
    raw: &str,
    offset: u64,
    stored: u64,
    long_names: Option<(usize, usize)>,
) -> Result<(String, u64), String> {
    let Some((start, end)) = long_names else {
        return Ok((raw.to_string(), stored));
    };
    let table = bytes
        .get(start..end)
        .ok_or("ar long name is outside the name table")?;
    Ok((name_in_table(table, offset)?, stored))
}

fn name_in_table(table: &[u8], offset: u64) -> Result<String, String> {
    let offset = usize::try_from(offset).map_err(|_| "ar long name is outside the name table")?;
    if offset >= table.len() {
        return Err("ar long name is outside the name table".into());
    }
    let rest = &table[offset..];
    let limit = rest.len().min(NAME_CAP);
    let mut end = 0;
    while end < limit {
        if rest[end] == b'\n' {
            break;
        }
        if rest[end] == b'/' && rest.get(end + 1) == Some(&b'\n') {
            break;
        }
        end += 1;
    }
    Ok(text(&rest[..end]))
}

fn trim_slash(raw: &str) -> String {
    match raw.strip_suffix('/') {
        Some(name) => name.to_string(),
        None => raw.to_string(),
    }
}

fn decimal(field: &[u8], err: &str) -> Result<u64, String> {
    let text = trim_ends(field);
    if text.is_empty() || text.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(err.into());
    }
    let mut value: u64 = 0;
    for &byte in text {
        let digit = u64::from(byte - b'0');
        value = value
            .checked_mul(10)
            .and_then(|next| next.checked_add(digit))
            .ok_or(err)?;
    }
    Ok(value)
}

fn trim_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b' ')
        .map(|index| index + 1)
        .unwrap_or(0);
    &bytes[..end]
}

fn trim_ends(bytes: &[u8]) -> &[u8] {
    let bytes = trim_end(bytes);
    let start = bytes
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, mode: &str, size: u64) -> [u8; 60] {
        assert!(name.len() <= 16);
        assert!(mode.len() <= 8);
        let size_text = size.to_string();
        assert!(size_text.len() <= 10);
        let mut out = [b' '; 60];
        out[..name.len()].copy_from_slice(name.as_bytes());
        out[40..40 + mode.len()].copy_from_slice(mode.as_bytes());
        out[48..48 + size_text.len()].copy_from_slice(size_text.as_bytes());
        out[58] = b'`';
        out[59] = b'\n';
        out
    }

    fn one_member(name: &str, mode: &str, size: u64, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAGIC.len() + HEADER_LEN + body.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&header(name, mode, size));
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn one_member_shows_name_size_and_mode() {
        let bytes = one_member("libneed.o", "100644", 4, b"\x7fELF");
        assert!(is_ar(&bytes));
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].name, "libneed.o");
        assert_eq!(archive.members[0].size, 4);
        assert_eq!(archive.members[0].mode, "100644");
        assert!(!archive.more);
        assert!(archive
            .members
            .iter()
            .all(|member| member.name != "/" && member.name != "symbol-table"));
        let page = page::render("libneed.a", &archive, false);
        assert!(page.contains("format: ar"), "{page}");
        assert!(page.contains("libneed.o"), "{page}");
        assert!(page.contains("size: 4"), "{page}");
        assert!(page.contains("mode: 100644"), "{page}");
        assert!(!page.contains("symbol-table"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        assert!(!page.contains("\nkind:"), "{page}");
        assert!(!page.contains("\nsign:"), "{page}");
        assert!(!page.contains("\nregions:"), "{page}");
        assert!(!page.contains("\ncerts:"), "{page}");
        let json = page::render_json("libneed.a", &archive);
        assert!(json.contains(r#""format":"ar""#), "{json}");
        assert!(json.contains(r#""name":"libneed.o""#), "{json}");
        assert!(json.contains(r#""size":4"#), "{json}");
        assert!(json.contains(r#""mode":"100644""#), "{json}");
        assert!(json.contains(r#""more":false"#), "{json}");
        assert!(!json.contains(r#""load""#), "{json}");
        assert!(!json.contains(r#""kind""#), "{json}");
    }

    #[test]
    fn a_system_v_slash_is_trimmed() {
        let bytes = one_member("libneed.o/", "100644", 0, b"");
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[0].name, "libneed.o");
        let page = page::render("libneed.a", &archive, false);
        assert!(page.contains("libneed.o"), "{page}");
        assert!(!page.contains("libneed.o/"), "{page}");
    }

    #[test]
    fn a_bsd_long_name_reports_the_payload_size() {
        let mut body = b"libneed\0".to_vec();
        body.extend_from_slice(b"abcd");
        let bytes = one_member("#1/8", "100644", body.len() as u64, &body);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[0].name, "libneed");
        assert_eq!(archive.members[0].size, 4);
        assert_eq!(archive.members[0].mode, "100644");
        let page = page::render("libneed.a", &archive, false);
        assert!(page.contains("libneed"), "{page}");
        assert!(page.contains("size: 4"), "{page}");
    }

    #[test]
    fn a_bad_trailer_returns_an_error() {
        let mut bytes = one_member("libneed.o/", "100644", 4, b"abcd");
        bytes[MAGIC.len() + 58] = b'x';
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn a_size_past_the_buffer_returns_an_error() {
        let bytes = one_member("libneed.o/", "100644", 100, b"abcd");
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn is_ar_is_false_without_the_magic() {
        assert!(!is_ar(b""));
        assert!(!is_ar(b"!<arch>"));
        assert!(!is_ar(b"hello"));
        assert!(!is_ar(b"\n!<arch>\n"));
        assert!(is_ar(b"!<arch>\n"));
        assert!(parse(b"hello").is_err());
        assert!(parse(b"!<arch>").is_err());
    }

    #[test]
    fn an_odd_size_puts_the_next_header_on_an_even_offset() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&header("one/", "100644", 1));
        bytes.extend_from_slice(b"X");
        bytes.push(b'\n');
        let second = bytes.len();
        bytes.extend_from_slice(&header("two/", "100755", 1));
        bytes.extend_from_slice(b"Y");
        bytes.push(b'\n');
        assert_eq!(second % 2, 0);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), 2);
        assert_eq!(archive.members[0].name, "one");
        assert_eq!(archive.members[0].size, 1);
        assert_eq!(archive.members[0].mode, "100644");
        assert_eq!(archive.members[1].name, "two");
        assert_eq!(archive.members[1].size, 1);
        assert_eq!(archive.members[1].mode, "100755");
        let page = page::render("odd.a", &archive, false);
        assert!(page.contains("one"), "{page}");
        assert!(page.contains("two"), "{page}");
    }

    #[test]
    fn a_final_odd_member_can_omit_the_pad() {
        let bytes = one_member("a/", "100644", 1, b"Z");
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[0].name, "a");
        assert_eq!(archive.members[0].size, 1);
    }

    #[test]
    fn a_system_v_long_name_uses_the_name_table() {
        let table = b"path/libneed.o/\nshort.o/\n";
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&header("//", "100644", table.len() as u64));
        bytes.extend_from_slice(table);
        bytes.push(b'\n');
        bytes.extend_from_slice(&header("/0", "100644", 4));
        bytes.extend_from_slice(b"abcd");
        bytes.extend_from_slice(&header("/16", "100755", 2));
        bytes.extend_from_slice(b"YZ");
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[0].name, "//");
        assert_eq!(archive.members[0].size, table.len() as u64);
        assert_eq!(archive.members[1].name, "path/libneed.o");
        assert_eq!(archive.members[1].size, 4);
        assert_eq!(archive.members[2].name, "short.o");
        assert_eq!(archive.members[2].mode, "100755");
        let page = page::render("long.a", &archive, false);
        assert!(page.contains("path/libneed.o"), "{page}");
        assert!(page.contains("short.o"), "{page}");
    }

    #[test]
    fn a_long_name_stays_raw_without_a_name_table() {
        let early = one_member("/12", "100644", 0, b"");
        assert_eq!(parse(&early).unwrap().members[0].name, "/12");

        let mut later = MAGIC.to_vec();
        later.extend_from_slice(&header("/0", "100644", 0));
        let table = b"later.o/\n";
        later.extend_from_slice(&header("//", "100644", table.len() as u64));
        later.extend_from_slice(table);
        later.push(b'\n');
        let archive = parse(&later).unwrap();
        assert_eq!(archive.members[0].name, "/0");
        assert_eq!(archive.members[1].name, "//");
    }

    #[test]
    fn a_resolved_name_stops_at_256_bytes() {
        let mut table = vec![b'n'; 300];
        table.extend_from_slice(b"/\n");
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&header("//", "100644", table.len() as u64));
        bytes.extend_from_slice(&table);
        bytes.extend_from_slice(&header("/0", "100644", 0));
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[1].name.len(), NAME_CAP);
        assert!(archive.members[1].name.bytes().all(|byte| byte == b'n'));
    }

    #[test]
    fn a_bsd_name_over_256_returns_an_error() {
        let body = vec![b'a'; NAME_CAP + 1];
        let bytes = one_member("#1/257", "100644", body.len() as u64, &body);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn a_bsd_name_of_256_bytes_is_kept() {
        let mut body = vec![b'z'; NAME_CAP];
        body.extend_from_slice(b"OK");
        let bytes = one_member("#1/256", "100644", body.len() as u64, &body);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[0].name.len(), NAME_CAP);
        assert_eq!(archive.members[0].size, 2);
    }

    #[test]
    fn a_symbol_table_name_stays_a_slash() {
        let body = [0_u8, 1, 2, 3, 0xff, 0xfe, 0xfd, 0xfc];
        let bytes = one_member("/", "100644", body.len() as u64, &body);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].name, "/");
        assert_eq!(archive.members[0].size, 8);
        let page = page::render("lib.a", &archive, false);
        assert!(page.contains("format: ar"), "{page}");
        assert!(!page.contains("\nkind:"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
    }

    #[test]
    fn a_non_decimal_size_returns_an_error() {
        let mut bytes = one_member("a/", "100644", 1, b"Z");
        let size_at = MAGIC.len() + 48;
        bytes[size_at..size_at + 10].copy_from_slice(b"xxxxxxxx  ");
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn a_short_header_returns_an_error() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(b"short");
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn the_member_cap_sets_more() {
        let row = header("a/", "100644", 0);
        let mut bytes = MAGIC.to_vec();
        for _ in 0..MEMBER_CAP + 1 {
            bytes.extend_from_slice(&row);
        }
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), MEMBER_CAP);
        assert!(archive.more);
        let page = page::render("many.a", &archive, false);
        assert!(page.contains("more: true"), "{page}");
        let json = page::render_json("many.a", &archive);
        assert!(json.contains(r#""more":true"#), "{json}");
    }
}
