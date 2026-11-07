/*
---
why: This file reads one ustar archive.
uses: bininfo
how: bininfo calls this file when the bytes are ustar.
This file records the body offset and skips the body bytes.
---
*/

//! One ustar archive.
//! This file reads headers. This file does not unpack a member.

pub mod page;

const BLOCK: usize = 512;
const MEMBER_CAP: usize = 4096;
const NAME_CAP: u64 = 4096;
const SUM_AT: usize = 148;
const SUM_LEN: usize = 8;

/// One ustar member. `kind` is the typeflag word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub size: u64,
    pub kind: &'static str,
    pub mode: String,
    /// Start of the member body. The body is not copied.
    pub offset: u64,
}

/// One ustar archive. `more` is true when the member cap stops the walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    pub members: Vec<Member>,
    pub more: bool,
}

struct Head {
    name: String,
    size: u64,
    mode: String,
    flag: u8,
    kind: &'static str,
}

/// True when the five bytes at offset 257 are `ustar`.
/// A file shorter than 262 bytes is false.
pub fn is_tar(bytes: &[u8]) -> bool {
    bytes.get(257..262) == Some(b"ustar".as_slice())
}

/// Read each ustar header. This function does not unpack a member.
pub fn parse(bytes: &[u8]) -> Result<Archive, String> {
    if !is_tar(bytes) {
        return Err("not a tar file".into());
    }

    let mut members = Vec::new();
    let mut at = 0usize;
    let mut zeros = 0usize;
    let mut more = false;
    let mut next_name: Option<String> = None;

    while at < bytes.len() {
        let Some(block) = next_block(bytes, at)? else {
            break;
        };
        if is_zero_block(block) {
            zeros += 1;
            at = at.checked_add(BLOCK).ok_or("tar header is short")?;
            if zeros >= 2 {
                break;
            }
            continue;
        }
        zeros = 0;
        if members.len() >= MEMBER_CAP {
            more = true;
            break;
        }

        let head = read_head(block)?;
        let body_at = at.checked_add(BLOCK).ok_or("tar header is short")?;
        let (next, rename) = follow_name(bytes, body_at, &head)?;
        at = next;
        if head.flag == b'L' {
            next_name = rename;
            continue;
        }
        let name = next_name.take().unwrap_or(head.name);
        if head.flag == b'x' {
            next_name = rename;
        }
        members.push(Member {
            name,
            size: head.size,
            kind: head.kind,
            mode: head.mode,
            offset: body_at as u64,
        });
    }

    Ok(Archive { members, more })
}

/// Body bytes of one file member. A directory has no body.
pub fn body<'a>(bytes: &'a [u8], member: &Member) -> Option<&'a [u8]> {
    if member.kind != "file" {
        return None;
    }
    let at = usize::try_from(member.offset).ok()?;
    let len = usize::try_from(member.size).ok()?;
    let end = at.checked_add(len)?;
    bytes.get(at..end)
}

fn next_block(bytes: &[u8], at: usize) -> Result<Option<&[u8]>, String> {
    let Some(end) = at.checked_add(BLOCK) else {
        return Err("tar header is short".into());
    };
    if end <= bytes.len() {
        return Ok(Some(&bytes[at..end]));
    }
    let Some(tail) = bytes.get(at..) else {
        return Ok(None);
    };
    if tail.is_empty() || is_zero_block(tail) {
        return Ok(None);
    }
    Err("tar header is short".into())
}

fn is_zero_block(block: &[u8]) -> bool {
    block.iter().all(|&byte| byte == 0)
}

fn read_head(block: &[u8]) -> Result<Head, String> {
    if !magic_ok(block) {
        return Err("tar magic is wrong".into());
    }
    check_sum(block)?;
    let size = octal(slice(block, 124, 12)?).map_err(|_| "tar size is not octal".to_string())?;
    let mode = octal(slice(block, 100, 8)?).map_err(|_| "tar mode is not octal".to_string())?;
    let name = entry_name(slice(block, 0, 100)?, slice(block, 345, 155)?);
    let flag = *slice(block, 156, 1)?.first().ok_or("tar header is short")?;
    Ok(Head {
        name,
        size,
        mode: format!("{mode:o}"),
        flag,
        kind: kind_of(flag),
    })
}

fn magic_ok(block: &[u8]) -> bool {
    let Some(magic) = block.get(257..263) else {
        return false;
    };
    magic.starts_with(b"ustar") && (magic[5] == 0 || magic[5] == b' ')
}

fn check_sum(block: &[u8]) -> Result<(), String> {
    let stored = octal(slice(block, SUM_AT, SUM_LEN)?).map_err(|_| "tar checksum is wrong")?;
    if checksum(block) != stored {
        return Err("tar checksum is wrong".into());
    }
    Ok(())
}

/// Unsigned sum of the header bytes. The checksum field counts as spaces.
fn checksum(block: &[u8]) -> u64 {
    let mut sum = 0u64;
    for (index, &byte) in block.iter().enumerate() {
        if (SUM_AT..SUM_AT + SUM_LEN).contains(&index) {
            sum += u64::from(b' ');
        } else {
            sum += u64::from(byte);
        }
    }
    sum
}

fn follow_name(bytes: &[u8], at: usize, head: &Head) -> Result<(usize, Option<String>), String> {
    if matches!(head.flag, b'L' | b'K' | b'x') && head.size > NAME_CAP {
        return Err("tar name is too long".into());
    }
    let next = skip_body(bytes, at, head.size)?;
    let rename = match head.flag {
        b'L' => Some(trim_nul(body_bytes(bytes, at, head.size)?)),
        b'x' => pax_path(body_bytes(bytes, at, head.size)?),
        _ => None,
    };
    Ok((next, rename))
}

fn skip_body(bytes: &[u8], at: usize, size: u64) -> Result<usize, String> {
    let span = padded(size).ok_or("member body is outside this file")?;
    let span = usize::try_from(span).map_err(|_| "member body is outside this file")?;
    let next = at
        .checked_add(span)
        .ok_or("member body is outside this file")?;
    if next > bytes.len() {
        return Err("member body is outside this file".into());
    }
    Ok(next)
}

fn padded(size: u64) -> Option<u64> {
    let rem = size % BLOCK as u64;
    if rem == 0 {
        Some(size)
    } else {
        size.checked_add(BLOCK as u64 - rem)
    }
}

fn body_bytes(bytes: &[u8], at: usize, size: u64) -> Result<&[u8], String> {
    let len = usize::try_from(size).map_err(|_| "member body is outside this file")?;
    let end = at
        .checked_add(len)
        .ok_or("member body is outside this file")?;
    bytes
        .get(at..end)
        .ok_or_else(|| "member body is outside this file".to_string())
}

fn pax_path(body: &[u8]) -> Option<String> {
    if !body.is_ascii() {
        return None;
    }
    let mut at = 0usize;
    let mut found = None;
    while at < body.len() {
        if body[at] == 0 {
            break;
        }
        let start = at;
        let mut len = 0usize;
        let mut saw = false;
        while at < body.len() && body[at].is_ascii_digit() {
            saw = true;
            len = len
                .checked_mul(10)?
                .checked_add(usize::from(body[at] - b'0'))?;
            at += 1;
        }
        if !saw || at >= body.len() || body[at] != b' ' || len == 0 {
            break;
        }
        let Some(end) = start.checked_add(len) else {
            break;
        };
        if end > body.len() {
            break;
        }
        let Some(payload) = body.get(at.saturating_add(1)..end) else {
            break;
        };
        if let Some(value) = payload.strip_prefix(b"path=") {
            let value = value.strip_suffix(b"\n").unwrap_or(value);
            found = Some(String::from_utf8_lossy(value).into_owned());
        }
        at = end;
    }
    found
}

fn kind_of(flag: u8) -> &'static str {
    match flag {
        0 | b'0' => "file",
        b'5' => "dir",
        b'2' => "symlink",
        b'1' => "link",
        b'L' => "gnu-long-name",
        b'K' => "gnu-long-link",
        b'x' => "pax",
        _ => "other",
    }
}

fn entry_name(name: &[u8], prefix: &[u8]) -> String {
    let name = text_field(name);
    let prefix = text_field(prefix);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

fn text_field(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(field.len());
    let bytes = &field[..end];
    let end = bytes
        .iter()
        .rposition(|&byte| byte != b' ')
        .map(|index| index + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn trim_nul(body: &[u8]) -> String {
    let end = body
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).into_owned()
}

fn slice(block: &[u8], at: usize, len: usize) -> Result<&[u8], String> {
    let end = at.checked_add(len).ok_or("tar header is short")?;
    block
        .get(at..end)
        .ok_or_else(|| "tar header is short".to_string())
}

fn octal(field: &[u8]) -> Result<u64, ()> {
    let mut at = 0usize;
    while at < field.len() && (field[at] == b' ' || field[at] == 0) {
        at += 1;
    }
    if at == field.len() {
        return Ok(0);
    }
    let mut value = 0u64;
    let mut saw = false;
    while at < field.len() {
        let byte = field[at];
        if (b'0'..b'8').contains(&byte) {
            saw = true;
            value = value
                .checked_mul(8)
                .and_then(|next| next.checked_add(u64::from(byte - b'0')))
                .ok_or(())?;
            at += 1;
            continue;
        }
        break;
    }
    if !saw {
        return Err(());
    }
    while at < field.len() {
        if field[at] != b' ' && field[at] != 0 {
            return Err(());
        }
        at += 1;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, prefix: &str, mode: u64, size: u64, flag: u8) -> [u8; 512] {
        header_magic(name, prefix, mode, size, flag, 0)
    }

    fn header_magic(
        name: &str,
        prefix: &str,
        mode: u64,
        size: u64,
        flag: u8,
        magic6: u8,
    ) -> [u8; 512] {
        let mut block = [0u8; 512];
        write_field(&mut block[0..100], name.as_bytes());
        put_octal(&mut block[100..108], mode);
        put_octal(&mut block[124..136], size);
        block[156] = flag;
        block[257..262].copy_from_slice(b"ustar");
        block[262] = magic6;
        block[263..265].copy_from_slice(b"00");
        write_field(&mut block[345..500], prefix.as_bytes());
        let sum = checksum(&block);
        put_octal(&mut block[148..156], sum);
        block
    }

    fn write_field(field: &mut [u8], bytes: &[u8]) {
        let len = bytes.len().min(field.len());
        field[..len].copy_from_slice(&bytes[..len]);
    }

    fn put_octal(field: &mut [u8], value: u64) {
        let digits = field.len() - 1;
        let text = format!("{value:o}");
        assert!(text.len() <= digits);
        for slot in &mut field[..digits] {
            *slot = b'0';
        }
        let start = digits - text.len();
        field[start..digits].copy_from_slice(text.as_bytes());
        field[digits] = 0;
    }

    fn push_member(out: &mut Vec<u8>, name: &str, prefix: &str, mode: u64, flag: u8, body: &[u8]) {
        let size = u64::try_from(body.len()).unwrap();
        out.extend_from_slice(&header(name, prefix, mode, size, flag));
        out.extend_from_slice(body);
        let rem = body.len() % 512;
        if rem != 0 {
            out.resize(out.len() + (512 - rem), 0);
        }
    }

    #[test]
    fn a_file_member_lists_hello_txt() {
        let mut bytes = Vec::new();
        push_member(&mut bytes, "hello.txt", "", 0o644, b'0', b"hello");
        assert!(is_tar(&bytes));
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), 1);
        assert!(!archive.more);
        let member = &archive.members[0];
        assert_eq!(member.name, "hello.txt");
        assert_eq!(member.size, 5);
        assert_eq!(member.kind, "file");
        assert_eq!(member.mode, "644");
        let page = page::render("hello.tar", &archive, false);
        assert!(page.contains("format: tar"), "{page}");
        assert!(page.contains("hello.txt"), "{page}");
        assert!(page.contains("A tar archive has no start claim."), "{page}");
        assert!(page.contains("size: 5"), "{page}");
        assert!(page.contains("kind: file"), "{page}");
        assert!(page.contains("mode: 644"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        let json = page::render_json("hello.tar", &archive);
        assert!(json.contains(r#""format":"tar""#), "{json}");
        assert!(json.contains(r#""name":"hello.txt""#), "{json}");
        assert!(json.contains(r#""size":5"#), "{json}");
        assert!(json.contains(r#""kind":"file""#), "{json}");
        assert!(json.contains(r#""mode":"644""#), "{json}");
        assert!(json.contains(r#""more":false"#), "{json}");
        assert!(!json.contains(r#""load""#), "{json}");
    }

    #[test]
    fn a_prefix_joins_the_name() {
        let mut bytes = Vec::new();
        push_member(&mut bytes, "main.rs", "src", 0o644, b'0', b"");
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[0].name, "src/main.rs");
    }

    #[test]
    fn type_flags_set_the_kind() {
        let mut bytes = Vec::new();
        push_member(&mut bytes, "sub", "", 0o755, b'5', b"");
        push_member(&mut bytes, "link", "", 0o777, b'2', b"");
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members[0].kind, "dir");
        assert_eq!(archive.members[1].kind, "symlink");
    }

    #[test]
    fn a_bad_checksum_returns_err() {
        let mut block = header("hello.txt", "", 0o644, 0, b'0');
        block[0] ^= 0x1;
        assert!(is_tar(&block));
        assert!(parse(&block).is_err());
    }

    #[test]
    fn a_huge_size_returns_err() {
        let huge = header("big.bin", "", 0o644, 0o7777_7777_777, b'0');
        assert!(parse(&huge).is_err());
        let short = header("short.bin", "", 0o644, 1, b'0');
        assert!(parse(&short).is_err());
    }

    #[test]
    fn two_zero_blocks_end_the_archive() {
        let mut early = Vec::new();
        push_member(&mut early, "one.txt", "", 0o644, b'0', b"a");
        early.extend_from_slice(&[0u8; 512]);
        push_member(&mut early, "two.txt", "", 0o644, b'0', b"b");
        let archive = parse(&early).unwrap();
        assert_eq!(archive.members.len(), 2);

        let mut bytes = Vec::new();
        push_member(&mut bytes, "hello.txt", "", 0o644, b'0', b"hello");
        bytes.extend_from_slice(&[0u8; 1024]);
        push_member(&mut bytes, "hidden.txt", "", 0o644, b'0', b"nope");
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].name, "hello.txt");
        assert!(!archive.more);
    }

    #[test]
    fn bytes_without_ustar_are_not_tar() {
        assert!(!is_tar(b""));
        assert!(!is_tar(&[0u8; 261]));
        let mut noise = vec![0u8; 512];
        noise[257..262].copy_from_slice(b"xxxxx");
        assert!(!is_tar(&noise));
        assert!(parse(&[]).is_err());
        assert!(parse(&[0u8; 10]).is_err());
        assert!(parse(&noise).is_err());

        let mut short = vec![0u8; 300];
        short[257..262].copy_from_slice(b"ustar");
        assert!(is_tar(&short));
        assert!(parse(&short).is_err());

        let spaced = header_magic("a.txt", "", 0o644, 0, b'0', b' ');
        assert!(is_tar(&spaced));
        assert_eq!(parse(&spaced).unwrap().members[0].name, "a.txt");
    }
}
