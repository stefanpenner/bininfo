/*
---
why: This file reads the headers of one cpio archive.
uses: bininfo
how: bininfo calls this file for a cpio magic in the first six bytes.
This file records each member body offset.
This file does not copy a member body.
---
*/

//! One cpio archive. The headers name each member.
//! This module records each body offset. It does not copy a member body.

pub mod page;

const MEMBER_CAP: usize = 4096;
const NAME_CAP: u64 = 4096;
const NEWC_HEADER: usize = 110;
const ODC_HEADER: usize = 76;
const TRAILER: &str = "TRAILER!!!";

/// One member. The mode field keeps the header digits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub size: u64,
    pub mode: String,
    /// First payload byte.
    pub offset: u64,
}

/// One archive. The more field is true at the member cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    pub profile: &'static str,
    pub members: Vec<Member>,
    pub more: bool,
}

struct Header {
    name: String,
    size: u64,
    mode: String,
    next: usize,
    offset: u64,
    trailer: bool,
}

/// This function returns true for magic 070701, 070702, or 070707.
pub fn is_cpio(bytes: &[u8]) -> bool {
    profile_of(bytes).is_some()
}

/// This function reads each header and records the body offset.
pub fn parse(bytes: &[u8]) -> Result<Archive, String> {
    let profile = profile_of(bytes).ok_or_else(|| "not a cpio file".to_string())?;
    let mut members = Vec::new();
    let mut at = 0usize;
    let mut more = false;
    while at < bytes.len() {
        let header = read_header(bytes, at, profile)?;
        at = header.next;
        if header.trailer {
            break;
        }
        if members.len() == MEMBER_CAP {
            more = true;
            break;
        }
        members.push(Member {
            name: header.name,
            size: header.size,
            mode: header.mode,
            offset: header.offset,
        });
    }
    Ok(Archive {
        profile,
        members,
        more,
    })
}

fn profile_of(bytes: &[u8]) -> Option<&'static str> {
    match bytes.get(..6) {
        Some(b"070701") => Some("newc"),
        Some(b"070702") => Some("crc"),
        Some(b"070707") => Some("odc"),
        _ => None,
    }
}

fn read_header(bytes: &[u8], at: usize, profile: &str) -> Result<Header, String> {
    let header = match profile {
        "odc" => read_odc(bytes, at)?,
        "crc" => read_hex(bytes, at, b"070702")?,
        _ => read_hex(bytes, at, b"070701")?,
    };
    if header.next <= at {
        return Err("cpio header is outside this file".into());
    }
    Ok(header)
}

fn read_hex(bytes: &[u8], at: usize, magic: &[u8]) -> Result<Header, String> {
    need(bytes, at, NEWC_HEADER)?;
    expect_magic(bytes, at, magic)?;
    let mode = field_str(bytes, at + 14, 8)?.to_string();
    parse_num(&mode, 16)?;
    let size = field_num(bytes, at + 54, 8, 16)?;
    let namesize = field_num(bytes, at + 94, 8, 16)?;
    let _check = field_num(bytes, at + 102, 8, 16)?;
    let (name, name_end) = take_name(bytes, at + NEWC_HEADER, namesize)?;
    let data_at = align4(name_end)?;
    let next = skip_body(bytes, name_end, size, true)?;
    Ok(make_header(name, size, mode, next, data_at))
}

// The odc header is 76 bytes.
// mtime and filesize are 11 octal digits.
fn read_odc(bytes: &[u8], at: usize) -> Result<Header, String> {
    need(bytes, at, ODC_HEADER)?;
    expect_magic(bytes, at, b"070707")?;
    let mode = field_str(bytes, at + 18, 6)?.to_string();
    parse_num(&mode, 8)?;
    let namesize = field_num(bytes, at + 59, 6, 8)?;
    let size = field_num(bytes, at + 65, 11, 8)?;
    let (name, name_end) = take_name(bytes, at + ODC_HEADER, namesize)?;
    let next = skip_body(bytes, name_end, size, false)?;
    Ok(make_header(name, size, mode, next, name_end))
}

fn make_header(name: String, size: u64, mode: String, next: usize, offset: usize) -> Header {
    let trailer = name == TRAILER;
    Header {
        name,
        size,
        mode,
        next,
        offset: offset as u64,
        trailer,
    }
}

fn take_name(bytes: &[u8], at: usize, namesize: u64) -> Result<(String, usize), String> {
    if namesize == 0 {
        return Err("cpio name is empty".into());
    }
    if namesize > NAME_CAP {
        return Err("cpio name is too long".into());
    }
    let len = usize::try_from(namesize).map_err(|_| "cpio name is too long".to_string())?;
    let end = at
        .checked_add(len)
        .ok_or_else(|| "cpio name is outside this file".to_string())?;
    if end > bytes.len() {
        return Err("cpio name is outside this file".into());
    }
    let raw = &bytes[at..end];
    let cut = match raw.iter().position(|byte| *byte == 0) {
        Some(cut) => cut,
        None => raw.len(),
    };
    let name = String::from_utf8_lossy(&raw[..cut]).into_owned();
    Ok((name, end))
}

fn skip_body(bytes: &[u8], name_end: usize, size: u64, align: bool) -> Result<usize, String> {
    let err = "cpio member is outside this file";
    if !align {
        let data_end = add_len(name_end, size)?;
        if data_end > bytes.len() {
            return Err(err.into());
        }
        return Ok(data_end);
    }
    if size == 0 && name_end == bytes.len() {
        return Ok(name_end);
    }
    let data_at = align4(name_end)?;
    if data_at > bytes.len() {
        return Err(err.into());
    }
    let data_end = add_len(data_at, size)?;
    if data_end > bytes.len() {
        return Err(err.into());
    }
    if data_end == bytes.len() {
        return Ok(data_end);
    }
    let next = align4(data_end)?;
    if next > bytes.len() {
        return Err(err.into());
    }
    Ok(next)
}

fn align4(at: usize) -> Result<usize, String> {
    let rem = at % 4;
    if rem == 0 {
        return Ok(at);
    }
    at.checked_add(4 - rem)
        .ok_or_else(|| "cpio member is outside this file".to_string())
}

fn add_len(at: usize, size: u64) -> Result<usize, String> {
    let size = usize::try_from(size).map_err(|_| "cpio member is outside this file".to_string())?;
    at.checked_add(size)
        .ok_or_else(|| "cpio member is outside this file".to_string())
}

fn need(bytes: &[u8], at: usize, len: usize) -> Result<(), String> {
    let end = at
        .checked_add(len)
        .ok_or_else(|| "cpio header is outside this file".to_string())?;
    if end > bytes.len() {
        return Err("cpio header is outside this file".into());
    }
    Ok(())
}

fn expect_magic(bytes: &[u8], at: usize, magic: &[u8]) -> Result<(), String> {
    let end = at
        .checked_add(magic.len())
        .ok_or_else(|| "cpio header is outside this file".to_string())?;
    let got = bytes
        .get(at..end)
        .ok_or_else(|| "cpio header is outside this file".to_string())?;
    if got != magic {
        return Err("cpio header magic is wrong".into());
    }
    Ok(())
}

fn field_num(bytes: &[u8], at: usize, len: usize, radix: u32) -> Result<u64, String> {
    parse_num(field_str(bytes, at, len)?, radix)
}

fn field_str(bytes: &[u8], at: usize, len: usize) -> Result<&str, String> {
    let end = at
        .checked_add(len)
        .ok_or_else(|| "cpio header is outside this file".to_string())?;
    let raw = bytes
        .get(at..end)
        .ok_or_else(|| "cpio header is outside this file".to_string())?;
    std::str::from_utf8(raw).map_err(|_| "cpio header field is not a number".to_string())
}

fn parse_num(text: &str, radix: u32) -> Result<u64, String> {
    if !digits(text, radix) {
        return Err("cpio header field is not a number".into());
    }
    u64::from_str_radix(text, radix).map_err(|_| "cpio header field is not a number".to_string())
}

fn digits(text: &str, radix: u32) -> bool {
    if text.is_empty() {
        return false;
    }
    text.bytes().all(|byte| match radix {
        8 => matches!(byte, b'0'..=b'7'),
        _ => byte.is_ascii_hexdigit(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(magic: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, body) in files {
            push_member(&mut out, magic, name, body, 0o100644);
        }
        push_member(&mut out, magic, "TRAILER!!!", b"", 0);
        out
    }

    fn push_member(out: &mut Vec<u8>, magic: &str, name: &str, body: &[u8], mode: u32) {
        let namesize = u32::try_from(name.len() + 1).expect("name fits");
        let filesize = u64::try_from(body.len()).expect("body fits");
        let header = if magic == "070707" {
            odc_header(mode, namesize, filesize)
        } else {
            hex_header(magic, mode, namesize, filesize)
        };
        let want = if magic == "070707" { 76 } else { 110 };
        assert_eq!(header.len(), want, "{header}");
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        if magic == "070707" {
            out.extend_from_slice(body);
            return;
        }
        pad4(out);
        out.extend_from_slice(body);
        pad4(out);
    }

    fn hex_header(magic: &str, mode: u32, namesize: u32, filesize: u64) -> String {
        format!(
            "{magic}{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{filesize:08x}{maj:08x}{min:08x}{rmaj:08x}{rmin:08x}{namesize:08x}{check:08x}",
            ino = 0u32,
            uid = 0u32,
            gid = 0u32,
            nlink = 1u32,
            mtime = 0u32,
            maj = 0u32,
            min = 0u32,
            rmaj = 0u32,
            rmin = 0u32,
            check = 0u32,
        )
    }

    fn odc_header(mode: u32, namesize: u32, filesize: u64) -> String {
        format!(
            "070707{dev:06o}{ino:06o}{mode:06o}{uid:06o}{gid:06o}{nlink:06o}{rdev:06o}{mtime:011o}{namesize:06o}{filesize:011o}",
            dev = 0u32,
            ino = 0u32,
            uid = 0u32,
            gid = 0u32,
            nlink = 1u32,
            rdev = 0u32,
            mtime = 0u32,
        )
    }

    fn pad4(out: &mut Vec<u8>) {
        let pad = (4 - (out.len() % 4)) % 4;
        out.resize(out.len() + pad, 0);
    }

    fn jpeg() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 8, 0, 2, 0, 3, 3];
        out.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0, 0xff, 0xd9]);
        out
    }

    #[test]
    fn a_step_reads_the_detected_member() {
        let photo = jpeg();
        let bytes = archive("070701", &[("photo.jpg", photo.as_slice())]);
        let file = crate::open(&bytes, false).unwrap();
        let page = crate::render("a.cpio", &file, false, false);
        assert!(page.contains("format: cpio"), "{page}");
        assert!(!page.contains("format: jpeg"), "{page}");
        let one = crate::step(&bytes, &["photo.jpg"], false, false).unwrap();
        assert!(one.contains("format: jpeg"), "{one}");
        assert!(one.contains("width: 3"), "{one}");
        assert!(crate::step(&bytes, &["missing.jpg"], false, false).is_none());
    }

    #[test]
    fn a_newc_archive_lists_hello() {
        let bytes = archive("070701", &[("hello", b"")]);
        assert!(is_cpio(&bytes));
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.profile, "newc");
        assert!(!archive.more);
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].name, "hello");
        assert_eq!(archive.members[0].size, 0);
        assert_eq!(archive.members[0].mode, "000081a4");
        let page = page::render("a.cpio", &archive, false);
        assert!(page.contains("format: cpio"), "{page}");
        assert!(page.contains("profile: newc"), "{page}");
        assert!(page.contains("hello"), "{page}");
        assert!(page.contains("000081a4 file"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        assert!(!page.contains("\nkind:"), "{page}");
        assert!(!page.contains("\nsign:"), "{page}");
        let json = page::render_json("a.cpio", &archive);
        assert!(json.contains(r#""format":"cpio""#), "{json}");
        assert!(json.contains(r#""profile":"newc""#), "{json}");
        assert!(json.contains(r#""mode":"000081a4""#), "{json}");
        assert!(!json.contains(r#""load""#), "{json}");
        assert!(!json.contains(r#""kind""#), "{json}");
    }

    #[test]
    fn a_crc_archive_uses_the_crc_profile() {
        let bytes = archive("070702", &[("note", b"hi")]);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.profile, "crc");
        assert_eq!(archive.members[0].name, "note");
        assert_eq!(archive.members[0].size, 2);
        let page = page::render("a.cpio", &archive, false);
        assert!(page.contains("profile: crc"), "{page}");
    }

    #[test]
    fn an_odc_archive_lists_the_member_name() {
        let bytes = archive("070707", &[("hello", b"")]);
        assert!(is_cpio(&bytes));
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.profile, "odc");
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].name, "hello");
        assert_eq!(archive.members[0].mode, "100644");
        let page = page::render("a.cpio", &archive, false);
        assert!(page.contains("profile: odc"), "{page}");
        assert!(page.contains("hello"), "{page}");
        assert!(page.contains("100644 file"), "{page}");
    }

    #[test]
    fn the_trailer_is_not_a_member() {
        let bytes = archive("070701", &[("hello", b"")]);
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), 1);
        assert!(archive
            .members
            .iter()
            .all(|member| member.name != "TRAILER!!!"));
    }

    #[test]
    fn a_namesize_past_the_buffer_returns_an_error() {
        let bytes = hex_header("070701", 0o100644, 32, 0);
        assert!(parse(bytes.as_bytes()).is_err());
        let long = hex_header("070701", 0o100644, 4097, 0);
        assert!(parse(long.as_bytes()).is_err());
    }

    #[test]
    fn a_filesize_past_the_buffer_returns_an_error() {
        let mut bytes = hex_header("070701", 0o100644, 6, 0xffff_ffff).into_bytes();
        bytes.extend_from_slice(b"hello\0");
        assert!(parse(&bytes).is_err());
        assert!(bytes.len() < 4096);
    }

    #[test]
    fn is_cpio_rejects_an_empty_slice_and_a_wrong_magic() {
        assert!(!is_cpio(b""));
        assert!(!is_cpio(b"070700"));
        assert!(!is_cpio(b"07070"));
        assert!(is_cpio(b"070701"));
        assert!(is_cpio(b"070702"));
        assert!(is_cpio(b"070707"));
        assert!(parse(b"").is_err());
        assert!(parse(b"070700").is_err());
    }

    #[test]
    fn mode_kind_words_cover_dir_and_symlink() {
        let mut bytes = Vec::new();
        push_member(&mut bytes, "070701", "dir", b"", 0o040755);
        push_member(&mut bytes, "070701", "link", b"", 0o120777);
        push_member(&mut bytes, "070701", "TRAILER!!!", b"", 0);
        let archive = parse(&bytes).unwrap();
        let page = page::render("a.cpio", &archive, false);
        assert!(page.contains("000041ed dir"), "{page}");
        assert!(page.contains("0000a1ff symlink"), "{page}");
    }

    #[test]
    fn the_member_cap_sets_more() {
        let mut bytes = Vec::new();
        for _ in 0..MEMBER_CAP + 1 {
            push_member(&mut bytes, "070701", "a", b"", 0o100644);
        }
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), MEMBER_CAP);
        assert!(archive.more);
        assert!(archive.members.iter().all(|member| member.name == "a"));
    }
}
