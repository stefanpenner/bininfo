/*
---
why: This file reads one Wasm module header and its section list.
uses: bininfo
how: bininfo calls this file for the Wasm magic.
This file records section names, imports, exports, memory limits, and the start index.
This file does not run the module.
---
*/

//! One Wasm module. The header is magic and a version word.
//! This module lists sections. It does not run code.

pub mod page;

const MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
const SECTION_CAP: usize = 256;
const IMPORT_CAP: usize = 4096;
const EXPORT_CAP: usize = 4096;
const NAME_CAP: u32 = 4096;

/// One Wasm import. `kind` is func, table, memory, or global.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub kind: &'static str,
}

/// One Wasm export. `index` is the item index in its own space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub kind: &'static str,
    pub index: u64,
}

/// One Wasm module. `start` is the start-section index.
/// It is not a start claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub version: u32,
    pub sections: Vec<&'static str>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub memory: Option<(u64, Option<u64>)>,
    pub start: Option<u64>,
    pub more: bool,
}

/// True when the bytes have Wasm magic and room for a version word.
/// A version other than 1 still matches. `parse` accepts only version 1.
pub fn is_wasm(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes.get(..4) == Some(MAGIC.as_slice())
}

/// Read one Wasm module. This function does not run the module.
pub fn parse(bytes: &[u8]) -> Result<Module, String> {
    let version = read_version(bytes)?;
    let mut module = Module {
        version,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        memory: None,
        start: None,
        more: false,
    };
    let mut at = 8usize;
    while at < bytes.len() {
        at = read_section(bytes, at, &mut module)?;
    }
    Ok(module)
}

fn read_version(bytes: &[u8]) -> Result<u32, String> {
    if !is_wasm(bytes) {
        return Err("wasm magic is missing".to_string());
    }
    let raw = bytes.get(4..8).ok_or("wasm magic is missing")?;
    let mut word = [0u8; 4];
    word.copy_from_slice(raw);
    let version = u32::from_le_bytes(word);
    if version != 1 {
        return Err("wasm version is not 1".to_string());
    }
    Ok(version)
}

fn read_section(bytes: &[u8], at: usize, module: &mut Module) -> Result<usize, String> {
    let id = *bytes.get(at).ok_or("wasm section is truncated")?;
    let mut cursor = at.checked_add(1).ok_or("wasm section is truncated")?;
    let size = read_leb(bytes, &mut cursor)?;
    let end = cursor
        .checked_add(size as usize)
        .ok_or("wasm section is past the end")?;
    // Each section moves the cursor. A stuck cursor would loop.
    if end > bytes.len() || end <= at {
        return Err("wasm section is past the end".to_string());
    }
    if module.sections.len() < SECTION_CAP {
        module.sections.push(section_name(id));
    } else {
        module.more = true;
    }
    let payload = bytes
        .get(cursor..end)
        .ok_or("wasm section is past the end")?;
    fill_section(id, payload, module)?;
    Ok(end)
}

fn fill_section(id: u8, payload: &[u8], module: &mut Module) -> Result<(), String> {
    match id {
        2 => fill_imports(payload, module),
        5 => fill_memory(payload, module),
        7 => fill_exports(payload, module),
        8 => fill_start(payload, module),
        _ => Ok(()),
    }
}

fn fill_imports(payload: &[u8], module: &mut Module) -> Result<(), String> {
    let mut at = 0usize;
    let count = read_leb(payload, &mut at)?;
    for _ in 0..count {
        let owner = read_name(payload, &mut at)?;
        let name = read_name(payload, &mut at)?;
        let kind_byte = read_u8(payload, &mut at)?;
        let kind = import_kind(payload, &mut at, kind_byte)?;
        if module.imports.len() < IMPORT_CAP {
            module.imports.push(Import {
                module: owner,
                name,
                kind,
            });
        } else {
            module.more = true;
        }
    }
    Ok(())
}

fn import_kind(payload: &[u8], at: &mut usize, kind: u8) -> Result<&'static str, String> {
    match kind {
        0 => {
            read_leb(payload, at)?;
            Ok("func")
        }
        1 => {
            read_u8(payload, at)?;
            read_limits(payload, at)?;
            Ok("table")
        }
        2 => {
            read_limits(payload, at)?;
            Ok("memory")
        }
        3 => {
            read_u8(payload, at)?;
            read_u8(payload, at)?;
            Ok("global")
        }
        _ => Err("wasm kind is unknown".to_string()),
    }
}

fn fill_exports(payload: &[u8], module: &mut Module) -> Result<(), String> {
    let mut at = 0usize;
    let count = read_leb(payload, &mut at)?;
    for _ in 0..count {
        let name = read_name(payload, &mut at)?;
        let kind_byte = read_u8(payload, &mut at)?;
        let kind = kind_name(kind_byte)?;
        let index = u64::from(read_leb(payload, &mut at)?);
        if module.exports.len() < EXPORT_CAP {
            module.exports.push(Export { name, kind, index });
        } else {
            module.more = true;
        }
    }
    Ok(())
}

fn fill_memory(payload: &[u8], module: &mut Module) -> Result<(), String> {
    let mut at = 0usize;
    let count = read_leb(payload, &mut at)?;
    for _ in 0..count {
        let limits = read_limits(payload, &mut at)?;
        if module.memory.is_none() {
            module.memory = Some(limits);
        } else {
            module.more = true;
        }
    }
    Ok(())
}

fn fill_start(payload: &[u8], module: &mut Module) -> Result<(), String> {
    let mut at = 0usize;
    let index = u64::from(read_leb(payload, &mut at)?);
    if module.start.is_some() {
        module.more = true;
    } else {
        module.start = Some(index);
    }
    Ok(())
}

fn read_limits(bytes: &[u8], at: &mut usize) -> Result<(u64, Option<u64>), String> {
    match read_u8(bytes, at)? {
        0x00 => Ok((u64::from(read_leb(bytes, at)?), None)),
        0x01 => {
            let min = u64::from(read_leb(bytes, at)?);
            let max = u64::from(read_leb(bytes, at)?);
            Ok((min, Some(max)))
        }
        _ => Err("wasm limits flag is unknown".to_string()),
    }
}

fn read_name(bytes: &[u8], at: &mut usize) -> Result<String, String> {
    let len = read_leb(bytes, at)?;
    if len > NAME_CAP {
        return Err("wasm name is too long".to_string());
    }
    let end = at
        .checked_add(len as usize)
        .ok_or("wasm name is past the end")?;
    let raw = bytes.get(*at..end).ok_or("wasm name is past the end")?;
    *at = end;
    Ok(String::from_utf8_lossy(raw).into_owned())
}

/// A u32 LEB uses at most 5 bytes. A longer word is an error.
fn read_leb(bytes: &[u8], at: &mut usize) -> Result<u32, String> {
    let mut value = 0u32;
    let mut shift = 0u32;
    let mut taken = 0u32;
    loop {
        if taken == 5 {
            return Err("wasm leb is too long".to_string());
        }
        let next = at.checked_add(1).ok_or("wasm leb is truncated")?;
        let byte = *bytes.get(*at).ok_or("wasm leb is truncated")?;
        *at = next;
        taken += 1;
        let bits = u32::from(byte & 0x7f);
        if shift == 28 && bits > 0x0f {
            return Err("wasm leb is too long".to_string());
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_u8(bytes: &[u8], at: &mut usize) -> Result<u8, String> {
    let next = at.checked_add(1).ok_or("wasm section is truncated")?;
    let byte = *bytes.get(*at).ok_or("wasm section is truncated")?;
    *at = next;
    Ok(byte)
}

fn kind_name(kind: u8) -> Result<&'static str, String> {
    match kind {
        0 => Ok("func"),
        1 => Ok("table"),
        2 => Ok("memory"),
        3 => Ok("global"),
        _ => Err("wasm kind is unknown".to_string()),
    }
}

fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "datacount",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = value;
        loop {
            let mut byte = (rest & 0x7f) as u8;
            rest >>= 7;
            if rest == 0 {
                out.push(byte);
                break;
            }
            byte |= 0x80;
            out.push(byte);
        }
        out
    }

    fn name(text: &str) -> Vec<u8> {
        let mut out = leb(u32::try_from(text.len()).unwrap());
        out.extend(text.as_bytes());
        out
    }

    fn section(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(leb(u32::try_from(payload.len()).unwrap()));
        out.extend(payload);
        out
    }

    fn wasm(version: u32, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x00, b'a', b's', b'm'];
        out.extend(version.to_le_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn an_empty_module_has_no_start_claim() {
        let bytes = wasm(1, &[]);
        assert!(is_wasm(&bytes));
        assert!(!is_wasm(&bytes[..7]));
        let module = parse(&bytes).unwrap();
        assert_eq!(module.version, 1);
        assert!(module.sections.is_empty());
        assert!(module.start.is_none());
        assert!(module.memory.is_none());
        let page = page::render("a.wasm", &module, false);
        assert!(page.contains("format: wasm"), "{page}");
        assert!(page.contains("A Wasm module has no start claim."), "{page}");
        assert!(page.contains("start: null"), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
        assert!(!page.contains("\nkind:"), "{page}");
        let json = page::render_json("a.wasm", &module);
        assert!(json.contains(r#""format":"wasm""#), "{json}");
        assert!(json.contains(r#""start":null"#), "{json}");
        assert!(!json.contains(r#""load""#), "{json}");
    }

    #[test]
    fn an_import_names_the_module_and_the_field() {
        let mut payload = leb(1);
        payload.extend(name("env"));
        payload.extend(name("puts"));
        payload.push(0);
        payload.extend(leb(0));
        let module = parse(&wasm(1, &section(2, &payload))).unwrap();
        assert_eq!(module.sections, ["import"]);
        assert_eq!(
            module.imports,
            vec![Import {
                module: "env".to_string(),
                name: "puts".to_string(),
                kind: "func",
            }]
        );
        let page = page::render("a.wasm", &module, false);
        assert!(page.contains("env.puts"), "{page}");
        assert!(page.contains("func"), "{page}");
    }

    #[test]
    fn an_export_names_a_function() {
        let mut payload = leb(1);
        payload.extend(name("answer"));
        payload.push(0);
        payload.extend(leb(1));
        let module = parse(&wasm(1, &section(7, &payload))).unwrap();
        assert_eq!(module.sections, ["export"]);
        assert_eq!(
            module.exports,
            vec![Export {
                name: "answer".to_string(),
                kind: "func",
                index: 1,
            }]
        );
        let page = page::render("a.wasm", &module, false);
        assert!(page.contains("answer"), "{page}");
        assert!(page.contains("func"), "{page}");
    }

    #[test]
    fn a_memory_section_keeps_min_and_max() {
        let mut payload = leb(1);
        payload.push(0x01);
        payload.extend(leb(1));
        payload.extend(leb(2));
        let module = parse(&wasm(1, &section(5, &payload))).unwrap();
        assert_eq!(module.memory, Some((1, Some(2))));
        let page = page::render("a.wasm", &module, false);
        assert!(page.contains("memory_min: 1"), "{page}");
        assert!(page.contains("memory_max: 2"), "{page}");
    }

    #[test]
    fn a_start_index_is_not_a_start_claim() {
        let module = parse(&wasm(1, &section(8, &leb(3)))).unwrap();
        assert_eq!(module.sections, ["start"]);
        assert_eq!(module.start, Some(3));
        let page = page::render("a.wasm", &module, false);
        assert!(page.contains("start: 3"), "{page}");
        assert!(page.contains("A Wasm module has no start claim."), "{page}");
        assert!(!page.contains("\nload:"), "{page}");
    }

    #[test]
    fn a_future_version_is_rejected() {
        let bytes = wasm(99, &[]);
        assert!(is_wasm(&bytes));
        let err = parse(&bytes).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn a_section_past_the_end_is_an_error() {
        let mut body = vec![1u8];
        body.extend(leb(100));
        let err = parse(&wasm(1, &body));
        assert!(err.is_err());
    }

    #[test]
    fn a_truncated_leb_is_an_error() {
        let err = parse(&wasm(1, &[1, 0x80]));
        assert!(err.is_err());
    }
}
