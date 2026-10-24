/*
---
why: This file checks certificate hits against a policy file.
uses: bininfo
how: The bininfo command reads a policy file and calls this file.
---
*/

//! Check certificate hits against a line-oriented policy.
//! A line that starts with `#` is a comment.
//! A rule line is `deny <id> <predicates> :: <message>` or `warn`.
//! The preferred match key is `spki`.
//! `spki` is the SHA-256 of the public key.
//! A `sha256` rule matches one certificate encoding.
//! A cross-sign of the same key has a different certificate hash.
//! `not <predicate>` matches a hit that fails that predicate.
//! `root` matches trust material that is not a pin.
//! `spki-not` matches a key that is outside the list.
//! `max <count>` reports matches after that count.
//! `issuer` matches the issuer common name or the issuer name.
//! `expired` and `not-yet` take `YYYY-MM-DDTHH:MM:SSZ`.
//! `rsa-below` matches an RSA key under that size.
//! `unknown-curve` matches a curve this scan does not name.
//! A deny makes the summary fail.
//! A warn does not.

use crate::certs::{Container, Curve, Encoding, Hit, Key, Kind, Role, Time};
use std::collections::HashSet;
use std::fmt::Write;

/// Pass or fail weight of one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// The summary fails.
    Deny,
    /// The summary stays a pass.
    Warn,
}

/// One policy file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    rules: Vec<Rule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    id: String,
    severity: Severity,
    message: String,
    preds: Vec<Pred>,
    max: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pred {
    Spki([u8; 32]),
    Sha256([u8; 32]),
    SpkiNot(Vec<[u8; 32]>),
    Cn(String),
    CnPrefix(String),
    Issuer(String),
    Kind(Kind),
    Encoding(Encoding),
    Container(Container),
    Place(String),
    Role(Role),
    Root,
    Expired(Time),
    NotYet(Time),
    RsaBelow(u16),
    UnknownCurve,
    Not(Box<Pred>),
}

/// One rule hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Rule id.
    pub id: String,
    /// Deny or warn.
    pub severity: Severity,
    /// Rule message.
    pub message: String,
    /// File offset of the hit.
    pub offset: usize,
    /// Length of the hit.
    pub length: usize,
    /// Section, overlay, or file.
    pub place: String,
    /// SHA-256 of the certificate or pin.
    pub sha256: [u8; 32],
    /// SHA-256 of the public key.
    pub spki_sha256: [u8; 32],
}

/// Violations in rule order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Each failed rule hit.
    pub violations: Vec<Violation>,
}

impl Report {
    /// Count of deny hits.
    pub fn denies(&self) -> usize {
        self.violations
            .iter()
            .filter(|item| item.severity == Severity::Deny)
            .count()
    }

    /// Count of warn hits.
    pub fn warns(&self) -> usize {
        self.violations
            .iter()
            .filter(|item| item.severity == Severity::Warn)
            .count()
    }

    /// True when a deny is present.
    pub fn failed(&self) -> bool {
        self.denies() > 0
    }
}

/// Parse one policy file.
pub fn parse(text: &str) -> Result<Policy, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rules = Vec::new();
    let mut seen = HashSet::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim().trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rule = parse_rule(line).map_err(|err| format!("policy:{}: {err}", index + 1))?;
        if !seen.insert(rule.id.clone()) {
            return Err(format!("policy:{}: duplicate rule {}", index + 1, rule.id));
        }
        rules.push(rule);
    }
    Ok(Policy { rules })
}

/// Apply `policy` to `hits`.
pub fn judge(hits: &[Hit], policy: &Policy) -> Report {
    let mut violations = Vec::new();
    for rule in &policy.rules {
        let matched: Vec<&Hit> = hits
            .iter()
            .filter(|hit| rule.preds.iter().all(|pred| matches_pred(hit, pred)))
            .collect();
        let flagged: &[&Hit] = match rule.max {
            Some(limit) => matched.get(limit..).unwrap_or(&[]),
            None => matched.as_slice(),
        };
        for hit in flagged {
            violations.push(Violation {
                id: rule.id.clone(),
                severity: rule.severity,
                message: rule.message.clone(),
                offset: hit.offset,
                length: hit.length,
                place: hit.place.clone(),
                sha256: hit.sha256,
                spki_sha256: hit.spki_sha256,
            });
        }
    }
    Report { violations }
}

/// Plain summary. A deny sets `result: fail`.
pub fn summary(file: &str, report: &Report) -> String {
    let mut out = String::new();
    let result = if report.failed() { "fail" } else { "pass" };
    let _ = writeln!(out, "file: {file}");
    let _ = writeln!(out, "result: {result}");
    let _ = writeln!(out, "denies: {}", report.denies());
    let _ = writeln!(out, "warns: {}", report.warns());
    for item in &report.violations {
        let severity = severity_name(item.severity);
        let _ = writeln!(
            out,
            "{severity} {} offset={} place={} spki={} sha256={} {}",
            item.id,
            item.offset,
            item.place,
            hex(&item.spki_sha256),
            hex(&item.sha256),
            item.message
        );
    }
    out
}

/// One JSON object for the same summary.
pub fn summary_json(file: &str, report: &Report) -> String {
    let mut out = String::from("{");
    push_str(&mut out, "file", file);
    out.push(',');
    push_str(
        &mut out,
        "result",
        if report.failed() { "fail" } else { "pass" },
    );
    let _ = write!(
        out,
        ",\"denies\":{},\"warns\":{}",
        report.denies(),
        report.warns()
    );
    out.push_str(",\"violations\":[");
    for (index, item) in report.violations.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_str(&mut out, "rule", &item.id);
        out.push(',');
        push_str(&mut out, "severity", severity_name(item.severity));
        let _ = write!(
            out,
            ",\"offset\":{},\"length\":{}",
            item.offset, item.length
        );
        out.push(',');
        push_str(&mut out, "place", &item.place);
        out.push(',');
        push_str(&mut out, "spki", &hex(&item.spki_sha256));
        out.push(',');
        push_str(&mut out, "sha256", &hex(&item.sha256));
        out.push(',');
        push_str(&mut out, "message", &item.message);
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Deny => "deny",
        Severity::Warn => "warn",
    }
}

fn push_str(out: &mut String, key: &str, value: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    out.push_str(&escape(value));
    out.push('"');
}

fn escape(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(other));
            }
            other => out.push(other),
        }
    }
    out
}

fn parse_rule(line: &str) -> Result<Rule, String> {
    let (body, message) = split_message(line).ok_or("expected :: before the message")?;
    let message = message.trim();
    if message.is_empty() {
        return Err("expected a message".into());
    }
    let tokens = tokenize(body)?;
    if tokens.len() < 3 {
        return Err("expected a severity, an id, and a predicate".into());
    }
    let severity = match tokens[0].as_str() {
        "deny" => Severity::Deny,
        "warn" => Severity::Warn,
        other => return Err(format!("unknown severity {other}")),
    };
    let id = tokens[1].clone();
    if !id_ok(&id) {
        return Err(format!("bad rule id {id}"));
    }
    let mut rest = &tokens[2..];
    let mut preds = Vec::new();
    let mut max = None;
    while !rest.is_empty() {
        if rest[0] == "max" {
            if max.is_some() {
                return Err("repeated max".into());
            }
            if rest.len() < 2 {
                return Err("expected a count".into());
            }
            max = Some(parse_count(&rest[1])?);
            rest = &rest[2..];
            continue;
        }
        let (pred, next) = parse_pred(rest)?;
        preds.push(pred);
        rest = next;
    }
    if preds.is_empty() {
        return Err("expected a predicate".into());
    }
    Ok(Rule {
        id,
        severity,
        message: message.to_string(),
        preds,
        max,
    })
}

fn split_message(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let mut quoted = false;
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] == b'"' {
            quoted = !quoted;
        }
        if !quoted && bytes[index..index + 4] == *b" :: " {
            return Some((&line[..index], &line[index + 4..]));
        }
        index += 1;
    }
    None
}

fn tokenize(input: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        if ch == '"' {
            let mut text = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some(next) => text.push(next),
                    None => return Err("open quote".into()),
                }
            }
            out.push(text);
            continue;
        }
        let mut text = String::from(ch);
        while let Some(next) = chars.peek() {
            if next.is_whitespace() {
                break;
            }
            text.push(chars.next().expect("peeked char"));
        }
        out.push(text);
    }
    Ok(out)
}

fn parse_pred<'a>(tokens: &'a [String]) -> Result<(Pred, &'a [String]), String> {
    if tokens.is_empty() {
        return Err("expected a predicate".into());
    }
    if tokens[0] == "not" {
        if tokens.len() < 2 || tokens[1] == "not" || tokens[1] == "max" {
            return Err("expected a predicate after not".into());
        }
        let (inner, rest) = parse_pred(&tokens[1..])?;
        return Ok((Pred::Not(Box::new(inner)), rest));
    }
    match tokens[0].as_str() {
        "spki" => Ok((Pred::Spki(parse_hex(need(tokens, 1)?)?), &tokens[2..])),
        "sha256" => Ok((Pred::Sha256(parse_hex(need(tokens, 1)?)?), &tokens[2..])),
        "spki-not" => {
            let mut hashes = Vec::new();
            let mut index = 1;
            while index < tokens.len() && is_hex(&tokens[index]) {
                hashes.push(parse_hex(&tokens[index])?);
                index += 1;
            }
            if hashes.is_empty() {
                return Err("expected a public key hash".into());
            }
            Ok((Pred::SpkiNot(hashes), &tokens[index..]))
        }
        "cn" => Ok((Pred::Cn(need(tokens, 1)?.to_string()), &tokens[2..])),
        "cn-prefix" => Ok((Pred::CnPrefix(need(tokens, 1)?.to_string()), &tokens[2..])),
        "issuer" => Ok((Pred::Issuer(need(tokens, 1)?.to_string()), &tokens[2..])),
        "kind" => Ok((Pred::Kind(parse_kind(need(tokens, 1)?)?), &tokens[2..])),
        "encoding" => Ok((
            Pred::Encoding(parse_encoding(need(tokens, 1)?)?),
            &tokens[2..],
        )),
        "container" => Ok((
            Pred::Container(parse_container(need(tokens, 1)?)?),
            &tokens[2..],
        )),
        "place" => Ok((Pred::Place(need(tokens, 1)?.to_string()), &tokens[2..])),
        "role" => Ok((Pred::Role(parse_role(need(tokens, 1)?)?), &tokens[2..])),
        "root" => Ok((Pred::Root, &tokens[1..])),
        "expired" => Ok((Pred::Expired(parse_stamp(need(tokens, 1)?)?), &tokens[2..])),
        "not-yet" => Ok((Pred::NotYet(parse_stamp(need(tokens, 1)?)?), &tokens[2..])),
        "rsa-below" => Ok((Pred::RsaBelow(parse_bits(need(tokens, 1)?)?), &tokens[2..])),
        "unknown-curve" => Ok((Pred::UnknownCurve, &tokens[1..])),
        other => Err(format!("unknown predicate {other}")),
    }
}

fn need<'a>(tokens: &'a [String], index: usize) -> Result<&'a str, String> {
    tokens
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| "expected a predicate value".into())
}

fn id_ok(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(ch) if ch.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn is_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_hex(text: &str) -> Result<[u8; 32], String> {
    if !is_hex(text) {
        return Err(format!("bad sha256 {text}"));
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("bad sha256 {text}"))?;
    }
    Ok(out)
}

fn parse_count(text: &str) -> Result<usize, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("bad count {text}"));
    }
    text.parse().map_err(|_| format!("bad count {text}"))
}

fn parse_bits(text: &str) -> Result<u16, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("bad size {text}"));
    }
    let bits: u16 = text.parse().map_err(|_| format!("bad size {text}"))?;
    if bits == 0 {
        return Err("bad size 0".into());
    }
    Ok(bits)
}

fn parse_kind(text: &str) -> Result<Kind, String> {
    match text {
        "full" => Ok(Kind::Full),
        "anchor" => Ok(Kind::Anchor),
        "body" => Ok(Kind::Body),
        "pin" => Ok(Kind::Pin),
        other => Err(format!("unknown kind {other}")),
    }
}

fn parse_encoding(text: &str) -> Result<Encoding, String> {
    match text {
        "der" => Ok(Encoding::Der),
        "pem" => Ok(Encoding::Pem),
        "base64" => Ok(Encoding::Base64),
        other => Err(format!("unknown encoding {other}")),
    }
}

fn parse_container(text: &str) -> Result<Container, String> {
    match text {
        "file" => Ok(Container::File),
        "gzip" => Ok(Container::Gzip),
        "zlib" => Ok(Container::Zlib),
        "zip" => Ok(Container::Zip),
        "sea" => Ok(Container::Sea),
        other => Err(format!("unknown container {other}")),
    }
}

fn parse_role(text: &str) -> Result<Role, String> {
    match text {
        "trust" => Ok(Role::Trust),
        "signer" => Ok(Role::Signer),
        other => Err(format!("unknown role {other}")),
    }
}

fn parse_stamp(text: &str) -> Result<Time, String> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(format!("bad time {text}"));
    }
    let year = number(&text[0..4])?;
    let month = number(&text[5..7])?;
    let day = number(&text[8..10])?;
    let hour = number(&text[11..13])?;
    let minute = number(&text[14..16])?;
    let second = number(&text[17..19])?;
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !valid_day(year, month, day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(format!("bad time {text}"));
    }
    Ok(Time {
        year: u16::try_from(year).unwrap_or(0),
        month: u8::try_from(month).unwrap_or(0),
        day: u8::try_from(day).unwrap_or(0),
        hour: u8::try_from(hour).unwrap_or(0),
        minute: u8::try_from(minute).unwrap_or(0),
        second: u8::try_from(second).unwrap_or(0),
    })
}

fn number(text: &str) -> Result<i32, String> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("bad time {text}"));
    }
    text.parse().map_err(|_| format!("bad time {text}"))
}

fn valid_day(year: i32, month: i32, day: i32) -> bool {
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=last).contains(&day)
}

fn leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn matches_pred(hit: &Hit, pred: &Pred) -> bool {
    match pred {
        Pred::Not(inner) => !matches_pred(hit, inner),
        Pred::Spki(hash) => hit.spki_sha256 == *hash,
        Pred::Sha256(hash) => hit.sha256 == *hash,
        Pred::SpkiNot(hashes) => !hashes.contains(&hit.spki_sha256),
        Pred::Cn(text) => hit.subject_cn.as_deref() == Some(text),
        Pred::CnPrefix(text) => hit
            .subject_cn
            .as_deref()
            .is_some_and(|name| name.starts_with(text)),
        Pred::Issuer(text) => {
            hit.issuer_cn.as_deref() == Some(text.as_str())
                || hit
                    .issuer_dn
                    .as_deref()
                    .is_some_and(|name| name.contains(text))
        }
        Pred::Kind(kind) => hit.kind == *kind,
        Pred::Encoding(encoding) => hit.encoding == *encoding,
        Pred::Container(container) => hit.container == *container,
        Pred::Place(place) => hit.place == *place,
        Pred::Role(role) => hit.role == *role,
        Pred::Root => is_root(hit),
        Pred::Expired(at) => hit.not_after.is_some_and(|end| end < *at),
        Pred::NotYet(at) => hit.not_before.is_some_and(|start| start > *at),
        Pred::RsaBelow(bits) => matches!(hit.key, Key::Rsa { bits: size } if size < *bits),
        Pred::UnknownCurve => matches!(
            hit.key,
            Key::Ec {
                curve: Curve::Other
            }
        ),
    }
}

fn is_root(hit: &Hit) -> bool {
    hit.role == Role::Trust && hit.kind != Kind::Pin
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs;

    const G3B: &str = "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105";
    const EMSIGN: &[u8] = include_bytes!("../tests/fixtures/emsign-ecc-g3.der");
    const G3B_PEM: &[u8] = include_bytes!("../tests/fixtures/em-dv-tls-g3b.pem");
    const G3B_SECTIGO: &[u8] = include_bytes!("../tests/fixtures/em-dv-tls-g3b-sectigo.pem");

    fn at(year: u16, month: u8, day: u8) -> Time {
        Time {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }

    fn sample() -> Hit {
        Hit {
            offset: 10,
            length: 20,
            kind: Kind::Full,
            encoding: Encoding::Der,
            sha256: [0x11; 32],
            spki_sha256: [0x22; 32],
            subject_cn: Some("Example CA".into()),
            issuer_cn: None,
            issuer_dn: None,
            not_before: Some(at(2020, 1, 1)),
            not_after: Some(at(2030, 1, 1)),
            key: Key::Ec { curve: Curve::P256 },
            place: "file".into(),
            role: Role::Trust,
            container: Container::File,
        }
    }

    fn one(text: &str, hit: &Hit) -> Report {
        let policy = parse(text).unwrap();
        judge(std::slice::from_ref(hit), &policy)
    }

    fn full_of(bytes: &[u8]) -> Hit {
        certs::scan(bytes)
            .into_iter()
            .find(|hit| hit.kind == Kind::Full)
            .expect("full certificate")
    }

    #[test]
    fn comments_quotes_and_bad_lines_parse() {
        let policy = parse(
            "\u{feff}# note\n\nwarn weak-name cn-prefix \"emSign \" :: subject starts with emSign\n",
        )
        .unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].id, "weak-name");
        assert_eq!(policy.rules[0].severity, Severity::Warn);
        assert!(parse("allow x spki ab :: no\n").is_err());
        assert!(parse("deny x spki ab :: no\n").is_err());
        assert!(parse("deny x cn \"open :: no\n").is_err());
        assert!(parse("deny bad id spki ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105 :: no\n").is_err());
        assert!(parse("deny a cn one :: \n").is_err());
        assert!(parse("deny a cn one\n").is_err());
        let dup = parse("deny a cn one :: first\ndeny a cn two :: second\n").unwrap_err();
        assert!(dup.contains("duplicate rule a"), "{dup}");
        assert!(parse("deny a not not kind pin :: no\n").is_err());
        assert!(parse("deny a max :: no\n").is_err());
    }

    #[test]
    fn sha256_and_spki_rules_match_one_fingerprint() {
        let mut hit = sample();
        hit.sha256[0] = 0xab;
        hit.spki_sha256[0] = 0xcd;
        let sha = hex(&hit.sha256);
        let spki = hex(&hit.spki_sha256);
        let by_cert = one(
            &format!("deny cert sha256 {sha} :: certificate hash\n"),
            &hit,
        );
        assert_eq!(by_cert.violations.len(), 1);
        assert_eq!(by_cert.violations[0].id, "cert");
        assert!(one(
            &format!("deny cert sha256 {spki} :: certificate hash\n"),
            &hit
        )
        .violations
        .is_empty());
        let by_key = one(&format!("deny key spki {spki} :: public key\n"), &hit);
        assert_eq!(by_key.violations[0].spki_sha256, hit.spki_sha256);
        assert!(one(&format!("deny key spki {sha} :: public key\n"), &hit)
            .violations
            .is_empty());
    }

    #[test]
    fn subject_cn_matches_an_exact_name_or_a_prefix() {
        let hit = sample();
        assert_eq!(
            one("deny exact cn \"Example CA\" :: exact name\n", &hit)
                .violations
                .len(),
            1
        );
        assert!(one("deny exact cn \"Example\" :: exact name\n", &hit)
            .violations
            .is_empty());
        assert_eq!(
            one("deny prefix cn-prefix Example :: prefix\n", &hit)
                .violations
                .len(),
            1
        );
        assert!(one("deny prefix cn-prefix Other :: prefix\n", &hit)
            .violations
            .is_empty());
    }

    #[test]
    fn issuer_matches_the_cn_or_the_name() {
        let mut hit = sample();
        hit.issuer_cn = Some("EM DV TLS CA - G3B".into());
        hit.issuer_dn = Some("C=NL,O=eMudhra BV,CN=EM DV TLS CA - G3B".into());
        hit.spki_sha256 = [9; 32];
        let report = one(
            "deny leaf issuer \"EM DV TLS CA - G3B\" :: issuer is compromised\n",
            &hit,
        );
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].id, "leaf");
        let mut named = sample();
        named.issuer_cn = None;
        named.issuer_dn = Some("CN=EM DV TLS CA - G3B,O=eMudhra BV".into());
        assert_eq!(
            one(
                "deny leaf issuer \"EM DV TLS CA - G3B\" :: issuer is compromised\n",
                &named
            )
            .violations
            .len(),
            1
        );
        assert!(one(
            "deny leaf issuer \"EM DV TLS CA - G3C\" :: other issuer\n",
            &hit
        )
        .violations
        .is_empty());
    }

    #[test]
    fn an_allowlist_requires_every_root_key() {
        let mut good = sample();
        good.spki_sha256 = [1; 32];
        let mut bad = sample();
        bad.offset = 40;
        bad.spki_sha256 = [2; 32];
        let mut signer = sample();
        signer.role = Role::Signer;
        signer.spki_sha256 = [3; 32];
        let allowed = hex(&[1; 32]);
        let text = format!("deny roots root spki-not {allowed} :: root key is not allowed\n");
        let report = judge(&[good, bad, signer], &parse(&text).unwrap());
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].offset, 40);
    }

    #[test]
    fn require_and_forbid_cover_kind_encoding_container_and_place() {
        let mut hit = sample();
        hit.kind = Kind::Pin;
        hit.encoding = Encoding::Pem;
        hit.container = Container::Zip;
        hit.place = "overlay".into();
        hit.role = Role::Trust;
        assert_eq!(
            one("deny pins kind pin :: a pin is forbidden\n", &hit)
                .violations
                .len(),
            1
        );
        assert_eq!(
            one(
                "deny need-der not encoding der :: encoding is not der\n",
                &hit
            )
            .violations
            .len(),
            1
        );
        assert!(one(
            "deny need-der not encoding pem :: encoding is not pem\n",
            &hit
        )
        .violations
        .is_empty());
        assert_eq!(
            one("deny zipped container zip :: a hit is in a zip\n", &hit)
                .violations
                .len(),
            1
        );
        let mut overlay = sample();
        overlay.place = "overlay".into();
        assert_eq!(
            one(
                "deny no-overlay root place overlay :: a root is in the overlay\n",
                &overlay
            )
            .violations
            .len(),
            1
        );
        let mut section = sample();
        section.place = ".rodata".into();
        assert!(one(
            "deny no-overlay root place overlay :: a root is in the overlay\n",
            &section
        )
        .violations
        .is_empty());
    }

    #[test]
    fn a_signer_outside_the_allowed_set_is_denied() {
        let mut signer = sample();
        signer.role = Role::Signer;
        signer.spki_sha256 = [4; 32];
        let allowed = hex(&[5; 32]);
        let text = format!(
            "deny signer-set role signer spki-not {allowed} :: signer key is not allowed\n"
        );
        assert_eq!(one(&text, &signer).violations.len(), 1);
        signer.spki_sha256 = [5; 32];
        assert!(one(&text, &signer).violations.is_empty());
        let mut root = sample();
        root.spki_sha256 = [4; 32];
        assert!(one(&text, &root).violations.is_empty());
    }

    #[test]
    fn a_count_limit_reports_roots_past_the_maximum() {
        let first = sample();
        let mut second = sample();
        second.offset = 30;
        let mut third = sample();
        third.offset = 50;
        let policy = parse("deny many root max 1 :: too many roots\n").unwrap();
        let report = judge(&[first.clone(), second, third], &policy);
        assert_eq!(report.violations.len(), 2);
        assert_eq!(report.violations[0].offset, 30);
        assert_eq!(report.violations[1].offset, 50);
        assert!(judge(&[first], &policy).violations.is_empty());
    }

    #[test]
    fn dates_and_weak_keys_match() {
        let mut old = sample();
        old.not_after = Some(at(2020, 1, 1));
        let mut fresh = sample();
        fresh.not_before = Some(at(2030, 1, 1));
        let mut open = sample();
        open.not_before = None;
        open.not_after = None;
        assert_eq!(
            one(
                "deny old expired 2026-10-24T00:00:00Z :: certificate is expired\n",
                &old
            )
            .violations
            .len(),
            1
        );
        assert!(one(
            "deny old expired 2026-10-24T00:00:00Z :: certificate is expired\n",
            &sample()
        )
        .violations
        .is_empty());
        assert!(one(
            "deny edge expired 2030-01-01T00:00:00Z :: certificate is expired\n",
            &sample()
        )
        .violations
        .is_empty());
        assert_eq!(
            one(
                "deny early not-yet 2026-10-24T00:00:00Z :: certificate is not valid yet\n",
                &fresh
            )
            .violations
            .len(),
            1
        );
        assert!(one(
            "deny old expired 2026-10-24T00:00:00Z :: certificate is expired\n",
            &open
        )
        .violations
        .is_empty());
        let mut rsa = sample();
        rsa.key = Key::Rsa { bits: 1024 };
        assert_eq!(
            one(
                "warn weak-rsa rsa-below 2048 :: RSA key is under 2048 bits\n",
                &rsa
            )
            .violations
            .len(),
            1
        );
        rsa.key = Key::Rsa { bits: 2048 };
        let strong = one(
            "warn weak-rsa rsa-below 2048 :: RSA key is under 2048 bits\n",
            &rsa,
        );
        assert!(strong.violations.is_empty());
        assert!(!strong.failed());
        let mut curve = sample();
        curve.key = Key::Ec {
            curve: Curve::Other,
        };
        let weak = one(
            "deny curve unknown-curve :: curve is not a known curve\n",
            &curve,
        );
        assert!(weak.failed());
        assert!(one(
            "deny curve unknown-curve :: curve is not a known curve\n",
            &sample()
        )
        .violations
        .is_empty());
    }

    #[test]
    fn a_warn_does_not_fail_the_summary() {
        let report = one("warn name cn \"Example CA\" :: noted\n", &sample());
        assert_eq!(report.warns(), 1);
        assert_eq!(report.denies(), 0);
        assert!(!report.failed());
        let text = summary("tiny", &report);
        assert!(text.contains("result: pass"), "{text}");
        assert!(text.contains("warn name "), "{text}");
        let json = summary_json("tiny", &report);
        assert!(json.contains(r#""result":"pass""#), "{json}");
        assert!(json.contains(r#""severity":"warn""#), "{json}");
    }

    #[test]
    fn the_emsign_fixture_is_denied() {
        let policy = parse(include_str!("../policies/distrusted.policy")).unwrap();
        let hits = certs::scan(EMSIGN);
        let report = judge(&hits, &policy);
        assert!(report.failed());
        assert!(report
            .violations
            .iter()
            .any(|item| item.id == "emsign-ecc-g3" && item.severity == Severity::Deny));
        let text = summary("emsign-ecc-g3.der", &report);
        assert!(text.contains("result: fail"), "{text}");
        assert!(text.contains("spki=8d417db2"), "{text}");
    }

    #[test]
    fn a_cross_sign_with_the_same_spki_is_denied() {
        let left = full_of(G3B_PEM);
        let right = full_of(G3B_SECTIGO);
        assert_ne!(left.sha256, right.sha256);
        assert_eq!(left.spki_sha256, right.spki_sha256);
        assert_eq!(hex(&left.spki_sha256), G3B);
        assert_eq!(left.issuer_cn.as_deref(), Some("emSign Root TLS CA - G3"));
        assert_eq!(right.issuer_cn.as_deref(), Some("AAA Certificate Services"));
        let policy = parse(include_str!("../policies/distrusted.policy")).unwrap();
        let left_report = judge(std::slice::from_ref(&left), &policy);
        let right_report = judge(std::slice::from_ref(&right), &policy);
        assert!(left_report
            .violations
            .iter()
            .any(|item| item.id == "em-dv-tls-g3b"));
        assert!(right_report
            .violations
            .iter()
            .any(|item| item.id == "em-dv-tls-g3b"));
        let only = parse(&format!(
            "deny one sha256 {} :: one encoding\n",
            hex(&left.sha256)
        ))
        .unwrap();
        assert_eq!(
            judge(std::slice::from_ref(&left), &only).violations.len(),
            1
        );
        assert!(judge(std::slice::from_ref(&right), &only)
            .violations
            .is_empty());
    }
}
