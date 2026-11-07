/*
---
why: This file reads the small JSON objects in an OCI image.
uses: bininfo
how: The OCI reader calls this file on oci-layout, index.json, and blob JSON.
A string stops at 4096 bytes.
This file does not read a layer body.
---
*/

//! A bounded JSON reader for OCI image documents.

const NODE_CAP: usize = 4096;
const STR_CAP: usize = 4096;
const DEPTH_CAP: usize = 16;

pub enum Val {
    Null,
    Bool,
    Num(u64),
    Str(String),
    Arr(Vec<Val>),
    Obj(Vec<(String, Val)>),
}

pub struct Doc {
    pub value: Val,
    pub truncated: bool,
}

struct Parse<'a> {
    bytes: &'a [u8],
    at: usize,
    nodes: usize,
    truncated: bool,
}

pub fn parse(bytes: &[u8]) -> Result<Doc, String> {
    let mut parse = Parse {
        bytes,
        at: 0,
        nodes: 0,
        truncated: false,
    };
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        parse.at = 3;
    }
    let value = parse.value(0)?;
    parse.skip();
    if parse.at != bytes.len() {
        return Err("oci json has trailing bytes".into());
    }
    Ok(Doc {
        value,
        truncated: parse.truncated,
    })
}

pub fn get<'a>(val: &'a Val, key: &str) -> Option<&'a Val> {
    let Val::Obj(pairs) = val else {
        return None;
    };
    pairs
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

pub fn as_str(val: &Val) -> Option<&str> {
    match val {
        Val::Str(text) => Some(text),
        _ => None,
    }
}

pub fn as_u64(val: &Val) -> Option<u64> {
    match val {
        Val::Num(number) => Some(*number),
        _ => None,
    }
}

pub fn as_arr(val: &Val) -> Option<&[Val]> {
    match val {
        Val::Arr(rows) => Some(rows),
        _ => None,
    }
}

impl<'a> Parse<'a> {
    fn value(&mut self, depth: usize) -> Result<Val, String> {
        if depth > DEPTH_CAP || self.nodes >= NODE_CAP {
            return Err("oci json is too deep".into());
        }
        self.nodes += 1;
        self.skip();
        let byte = self.peek().ok_or("oci json ends early")?;
        match byte {
            b'n' => self.lit(b"null", Val::Null),
            b't' => self.lit(b"true", Val::Bool),
            b'f' => self.lit(b"false", Val::Bool),
            b'"' => Ok(Val::Str(self.string()?)),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            b'-' => Err("oci json number is negative".into()),
            b'0'..=b'9' => Ok(Val::Num(self.number()?)),
            _ => Err("oci json value is wrong".into()),
        }
    }

    fn lit(&mut self, word: &[u8], value: Val) -> Result<Val, String> {
        let end = self
            .at
            .checked_add(word.len())
            .ok_or("oci json value is wrong")?;
        if self.bytes.get(self.at..end) != Some(word) {
            return Err("oci json value is wrong".into());
        }
        self.at = end;
        Ok(value)
    }

    fn array(&mut self, depth: usize) -> Result<Val, String> {
        self.at += 1;
        let mut rows = Vec::new();
        loop {
            self.skip();
            if self.peek() == Some(b']') {
                self.at += 1;
                return Ok(Val::Arr(rows));
            }
            if !rows.is_empty() {
                self.comma()?;
            }
            rows.push(self.value(depth + 1)?);
        }
    }

    fn object(&mut self, depth: usize) -> Result<Val, String> {
        self.at += 1;
        let mut pairs = Vec::new();
        loop {
            self.skip();
            if self.peek() == Some(b'}') {
                self.at += 1;
                return Ok(Val::Obj(pairs));
            }
            if !pairs.is_empty() {
                self.comma()?;
            }
            self.skip();
            if self.peek() != Some(b'"') {
                return Err("oci json key is wrong".into());
            }
            let key = self.string()?;
            self.skip();
            if self.peek() != Some(b':') {
                return Err("oci json key is wrong".into());
            }
            self.at += 1;
            pairs.push((key, self.value(depth + 1)?));
        }
    }

    fn comma(&mut self) -> Result<(), String> {
        self.skip();
        if self.peek() != Some(b',') {
            return Err("oci json value is wrong".into());
        }
        self.at += 1;
        Ok(())
    }

    fn number(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut saw = false;
        while let Some(byte) = self.peek() {
            if !byte.is_ascii_digit() {
                break;
            }
            saw = true;
            let digit = u64::from(byte - b'0');
            value = value
                .checked_mul(10)
                .and_then(|next| next.checked_add(digit))
                .ok_or("oci json number is too large")?;
            self.at += 1;
        }
        if !saw {
            return Err("oci json number is wrong".into());
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("oci json number is not an integer".into());
        }
        Ok(value)
    }

    fn string(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let byte = self.peek().ok_or("oci json string ends early")?;
            self.at += 1;
            match byte {
                b'"' => return Ok(String::from_utf8_lossy(&out).into_owned()),
                b'\\' => {
                    let esc = self.peek().ok_or("oci json string ends early")?;
                    self.at += 1;
                    let decoded = match esc {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{0008}',
                        b'f' => '\u{000c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode()?,
                        _ => return Err("oci json escape is wrong".into()),
                    };
                    self.push_char(&mut out, decoded);
                }
                byte if byte < 0x20 => return Err("oci json string is wrong".into()),
                byte => self.push_byte(&mut out, byte),
            }
        }
    }

    fn unicode(&mut self) -> Result<char, String> {
        let end = self.at.checked_add(4).ok_or("oci json string ends early")?;
        let raw = self
            .bytes
            .get(self.at..end)
            .ok_or("oci json string ends early")?;
        self.at = end;
        let text = std::str::from_utf8(raw).map_err(|_| "oci json escape is wrong")?;
        let code = u32::from_str_radix(text, 16).map_err(|_| "oci json escape is wrong")?;
        char::from_u32(code).ok_or_else(|| "oci json escape is wrong".into())
    }

    fn push_char(&mut self, out: &mut Vec<u8>, ch: char) {
        let mut buf = [0u8; 4];
        for byte in ch.encode_utf8(&mut buf).as_bytes() {
            self.push_byte(out, *byte);
        }
    }

    fn push_byte(&mut self, out: &mut Vec<u8>, byte: u8) {
        if out.len() >= STR_CAP {
            self.truncated = true;
            return;
        }
        out.push(byte);
    }

    fn skip(&mut self) {
        while let Some(byte) = self.peek() {
            if !matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                break;
            }
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
}
