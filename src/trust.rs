/*
---
why: This file judges each cert as valid or invalid.
uses: bininfo
how: The date check needs only the cert.
The bad list comes from public advisories, through curl, with a cache.
A missing list never fails the run. The cert is then judged by date alone.
---
*/

//! Cert verdicts: dates and a list of known bad certs.

use crate::certs::Hit;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(15 * 60);
const EMUDHRA: [&str; 2] = [
    "https://emudhra.we-have-a-problem.com/roots.json",
    "https://emudhra.we-have-a-problem.com/impacted-intermediates.json",
];
const EMUDHRA_PAGE: &str = "https://emudhra.we-have-a-problem.com/";
const MOZILLA_PAGE: &str = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReport";
const MOZILLA_REMOVED: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportPEMCSV";
const MOZILLA_REVOKED: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV";
const MOZILLA_REMOVED_PAGE: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReport";
const ONECRL_PAGE: &str = "https://wiki.mozilla.org/CA/Revocation_Checking_in_Firefox";
const ONECRL: &str =
    "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records";
const MOZILLA: &str = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV";

/// One cert on the bad list. Hashes are lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bad {
    pub sha256: String,
    pub spki_sha256: String,
    pub why: String,
    /// Where to read about it.
    pub url: String,
    /// `critical` (compromised or leaked), `revoked`, or `distrusted`.
    pub kind: String,
}

/// The bad list and where it came from.
#[derive(Clone, Debug, Default)]
pub struct Bads {
    pub list: Vec<Bad>,
    /// `fetched`, `cache`, `stale cache`, or `unavailable`.
    pub source: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    /// The cert has no dates and is not on the list.
    Unknown,
    /// Past notAfter. The text names the date.
    Expired(String),
    /// Before notBefore. The text names the date.
    NotYetValid(String),
    /// On a bad list: compromised, distrusted, or revoked.
    Distrusted {
        kind: String,
        why: String,
        url: String,
    },
}

impl Verdict {
    pub fn mark(&self) -> &'static str {
        match self {
            Verdict::Valid => "✓",
            Verdict::Unknown => "–",
            Verdict::Expired(_) | Verdict::NotYetValid(_) => "◷",
            Verdict::Distrusted { kind, .. } if kind == "critical" => "‼",
            Verdict::Distrusted { kind, .. } if kind == "revoked" => "⊘",
            Verdict::Distrusted { .. } => "✗",
        }
    }

    /// A stable word for JSON.
    pub fn status(&self) -> &'static str {
        match self {
            Verdict::Valid => "valid",
            Verdict::Unknown => "unknown",
            Verdict::Expired(_) => "expired",
            Verdict::NotYetValid(_) => "not_yet_valid",
            Verdict::Distrusted { kind, .. } if kind == "critical" => "critical",
            Verdict::Distrusted { kind, .. } if kind == "revoked" => "revoked",
            Verdict::Distrusted { .. } => "distrusted",
        }
    }

    pub fn reason(&self) -> Option<String> {
        match self {
            Verdict::Expired(date) => Some(format!("expired {date}")),
            Verdict::NotYetValid(date) => Some(format!("not valid until {date}")),
            Verdict::Distrusted { why, .. } => Some(why.clone()),
            _ => None,
        }
    }

    pub fn url(&self) -> Option<&str> {
        match self {
            Verdict::Distrusted { url, .. } if !url.is_empty() => Some(url),
            _ => None,
        }
    }
}

/// Judge one hit. `now` is Unix seconds. The bad list wins over dates.
pub fn judge(hit: &Hit, bads: &Bads, now: i64) -> Verdict {
    let sha = crate::summary::hex(&hit.sha256);
    let spki = crate::summary::hex(&hit.spki_sha256);
    if let Some(bad) = bads
        .list
        .iter()
        .find(|bad| bad.sha256 == sha || (!bad.spki_sha256.is_empty() && bad.spki_sha256 == spki))
    {
        return Verdict::Distrusted {
            kind: bad.kind.clone(),
            why: bad.why.clone(),
            url: bad.url.clone(),
        };
    }
    match (hit.not_before, hit.not_after) {
        (Some(from), _) if now < from => Verdict::NotYetValid(date(from)),
        (_, Some(to)) if now > to => Verdict::Expired(date(to)),
        (Some(_), Some(_)) => Verdict::Valid,
        _ => Verdict::Unknown,
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `YYYY-MM-DD` from Unix seconds.
pub fn date(secs: i64) -> String {
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn cache_file() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("BININFO_BAD_CACHE") {
        return Some(PathBuf::from(path));
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("bininfo").join("bad-certs-v4.tsv"))
}

/// Load the bad list. With `fetch`, a missing or old cache is refreshed with curl.
pub fn load(fetch: bool) -> Bads {
    let file = cache_file();
    let cached = file.as_ref().and_then(|f| std::fs::read_to_string(f).ok());
    let age = file
        .as_ref()
        .and_then(|f| std::fs::metadata(f).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok());
    let fresh = age.is_some_and(|a| a < TTL);
    if let (Some(text), true) = (&cached, fresh) {
        return Bads {
            list: from_tsv(text),
            source: "cache",
        };
    }
    if fetch {
        let list = fetch_all();
        if !list.is_empty() {
            if let Some(f) = &file {
                if let Some(dir) = f.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(f, to_tsv(&list));
            }
            return Bads {
                list,
                source: "fetched",
            };
        }
    }
    match cached {
        Some(text) => {
            // Rewrite the old list so a failed fetch is not retried until the TTL passes.
            if fetch {
                if let Some(f) = &file {
                    let _ = std::fs::write(f, &text);
                }
            }
            Bads {
                list: from_tsv(&text),
                source: "stale cache",
            }
        }
        None => Bads {
            list: Vec::new(),
            source: "unavailable",
        },
    }
}

fn fetch_all() -> Vec<Bad> {
    let mut list = Vec::new();
    for url in EMUDHRA {
        if let Some(text) = curl(url) {
            list.extend(parse_advisory(&text));
        }
    }
    if let Some(text) = curl(ONECRL) {
        list.extend(parse_onecrl(&text));
    }
    if let Some(text) = curl(MOZILLA) {
        list.extend(parse_mozilla(&text));
    }
    if let Some(text) = curl(MOZILLA_REMOVED) {
        list.extend(parse_removed(&text));
    }
    if let Some(text) = curl(MOZILLA_REVOKED) {
        list.extend(parse_revoked(&text));
    }
    list
}

fn curl(url: &str) -> Option<String> {
    let out = Command::new("curl")
        .args(["-fsSL", "-m", "20", url])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn to_tsv(list: &[Bad]) -> String {
    list.iter()
        .map(|b| format!("{}\t{}\t{}\t{}\t{}\n", b.sha256, b.spki_sha256, b.why, b.url, b.kind))
        .collect()
}

fn from_tsv(text: &str) -> Vec<Bad> {
    text.lines()
        .filter_map(|line| {
            let mut cols = line.splitn(5, '\t');
            Some(Bad {
                sha256: cols.next()?.to_string(),
                spki_sha256: cols.next()?.to_string(),
                why: cols.next()?.to_string(),
                url: cols.next().unwrap_or("").to_string(),
                kind: cols.next().unwrap_or("distrusted").to_string(),
            })
        })
        .collect()
}

/// Read the eMudhra advisory JSON. Each record has `name`, `sha256`, `spki_sha256`.
pub fn parse_advisory(text: &str) -> Vec<Bad> {
    let mut out = Vec::new();
    let mut name = String::new();
    let mut operator = String::new();
    let mut sha = String::new();
    for (key, value) in string_pairs(text) {
        match key.as_str() {
            "name" => name = value,
            "operator" => operator = value,
            "sha256" => sha = value.to_lowercase(),
            "spki_sha256" if !sha.is_empty() => {
                let other = Some(std::mem::take(&mut operator))
                    .filter(|o| !o.is_empty() && !o.eq_ignore_ascii_case("emudhra"));
                let (kind, why) = match other {
                    Some(op) => (
                        "distrusted",
                        format!("eMudhra advisory lists this {op} root as a signer of affected eMudhra CAs: {name}"),
                    ),
                    None => ("critical", format!("eMudhra CA compromise advisory: {name}")),
                };
                out.push(Bad {
                    sha256: std::mem::take(&mut sha),
                    spki_sha256: value.to_lowercase(),
                    why,
                    url: EMUDHRA_PAGE.to_string(),
                    kind: kind.into(),
                });
            }
            _ => {}
        }
    }
    out
}

// Every `"key": "value"` pair, in order. Enough for flat advisory JSON.
fn string_pairs(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some((key, after)) = next_string(rest) {
        let trimmed = after.trim_start();
        if let Some(value_part) = trimmed.strip_prefix(':') {
            if let Some(after_ws) = Some(value_part.trim_start()) {
                if after_ws.starts_with('"') {
                    if let Some((value, tail)) = next_string(after_ws) {
                        out.push((key, value));
                        rest = tail;
                        continue;
                    }
                }
            }
        }
        rest = after;
    }
    out
}

fn next_string(text: &str) -> Option<(String, &str)> {
    let start = text.find('"')? + 1;
    let mut out = String::new();
    let mut chars = text[start..].char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &text[start + i + 1..])),
            '\\' => {
                if let Some((_, n)) = chars.next() {
                    out.push(n);
                }
            }
            _ => out.push(c),
        }
    }
    None
}

/// Read Mozilla OneCRL, the list Firefox itself blocks. Only entries keyed by
/// public key hash can match here; issuer and serial entries need the serial.
pub fn parse_onecrl(text: &str) -> Vec<Bad> {
    let mut out = Vec::new();
    let (mut bug, mut subject) = (String::new(), String::new());
    for (key, value) in string_pairs(text) {
        match key.as_str() {
            "bug" => bug = value,
            "subject" => subject = value,
            "pubKeyHash" => {
                let Some(hash) = crate::certs::b64_decode(value.as_bytes()) else { continue };
                let name = crate::certs::b64_decode(subject.as_bytes())
                    .and_then(|der| der_common_name(&der))
                    .unwrap_or_else(|| "unnamed".into());
                let url = match bug.as_str() {
                    "" => ONECRL_PAGE.to_string(),
                    b if b.bytes().all(|c| c.is_ascii_digit()) => {
                        format!("https://bugzilla.mozilla.org/show_bug.cgi?id={b}")
                    }
                    b => b.to_string(),
                };
                out.push(Bad {
                    sha256: String::new(),
                    spki_sha256: crate::summary::hex(&hash),
                    why: format!("blocked by Mozilla OneCRL: {name}"),
                    url,
                    kind: "revoked".into(),
                });
            }
            "id" => {
                bug.clear();
                subject.clear();
            }
            _ => {}
        }
    }
    out
}

// The commonName (2.5.4.3) string in a DER name, if any.
fn der_common_name(der: &[u8]) -> Option<String> {
    let at = der.windows(3).position(|w| w == [0x55, 0x04, 0x03])? + 3;
    let len = *der.get(at + 1)? as usize;
    let text = der.get(at + 2..at + 2 + len)?;
    Some(String::from_utf8_lossy(text).into_owned())
}

/// Read the Mozilla CCADB roots CSV. A root with a distrust date is bad.
pub fn parse_mozilla(text: &str) -> Vec<Bad> {
    let mut rows = csv_rows(text).into_iter();
    let Some(head) = rows.next() else {
        return Vec::new();
    };
    let col = |name: &str| head.iter().position(|h| h.trim_start_matches('\u{feff}') == name);
    let (Some(name), Some(sha), Some(tls), Some(mail)) = (
        col("Common Name or Certificate Name"),
        col("SHA-256 Fingerprint"),
        col("Distrust for TLS After Date"),
        col("Distrust for S/MIME After Date"),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for row in rows {
        let get = |i: usize| row.get(i).map(|s| s.trim()).unwrap_or("");
        for (label, at) in [("TLS", tls), ("S/MIME", mail)] {
            if !get(at).is_empty() && !get(sha).is_empty() {
                out.push(Bad {
                    sha256: get(sha).to_lowercase(),
                    spki_sha256: String::new(),
                    why: format!("Mozilla distrusts {label} after {}: {}", get(at), get(name)),
                    url: MOZILLA_PAGE.to_string(),
                    kind: "distrusted".into(),
                });
                break;
            }
        }
    }
    out
}

/// Read the CCADB removed-roots CSV. Mozilla took these roots out of its store.
pub fn parse_removed(text: &str) -> Vec<Bad> {
    let mut out = Vec::new();
    for row in records(text) {
        let get = |k: &str| row.get(k).map(|s| s.trim()).unwrap_or("");
        let sha = get("SHA-256 Fingerprint");
        if sha.is_empty() {
            continue;
        }
        let when = get("Firefox Release When Removed");
        let bug = get("Removal Bug No. or Date");
        out.push(Bad {
            sha256: sha.to_lowercase(),
            spki_sha256: String::new(),
            why: format!(
                "removed from the Mozilla root store{}: {}",
                if when.is_empty() { String::new() } else { format!(" ({when})") },
                get("Root Certificate Name")
            ),
            url: if bug.starts_with("http") { bug.into() } else { MOZILLA_REMOVED_PAGE.into() },
            kind: "distrusted".into(),
        });
    }
    out
}

/// Read the CCADB revoked-intermediates CSV.
pub fn parse_revoked(text: &str) -> Vec<Bad> {
    let mut out = Vec::new();
    for row in records(text) {
        let get = |k: &str| row.get(k).map(|s| s.trim()).unwrap_or("");
        let sha = get("SHA-256 Fingerprint");
        if sha.is_empty() {
            continue;
        }
        let reason = get("RFC 5280 Revocation Reason Code");
        let reason = reason.split(") ").last().unwrap_or("");
        let status = get("Revocation Status").to_lowercase();
        let date = get("Date of Revocation");
        let mut why = format!("{status} (CCADB): {}", get("Certificate Subject Common Name"));
        if !reason.is_empty() {
            why.push_str(&format!(", {reason}"));
        }
        if !date.is_empty() {
            why.push_str(&format!(", {date}"));
        }
        out.push(Bad {
            sha256: sha.to_lowercase(),
            spki_sha256: String::new(),
            why,
            url: ONECRL_PAGE.into(),
            kind: if reason.contains("Compromise") { "critical" } else { "revoked" }.into(),
        });
    }
    out
}

// Each CSV row as a map from header to value.
fn records(text: &str) -> Vec<std::collections::HashMap<String, String>> {
    let mut rows = csv_rows(text).into_iter();
    let Some(head) = rows.next() else {
        return Vec::new();
    };
    let head: Vec<String> = head
        .into_iter()
        .map(|h| h.trim_start_matches('\u{feff}').to_string())
        .collect();
    rows.map(|row| head.iter().cloned().zip(row).collect()).collect()
}

fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, '\r') => {}
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_print_as_iso() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_709_251_200), "2024-03-01");
    }

    #[test]
    fn advisory_records_become_bad_entries() {
        let json = r#"[{"name":"Root A","sha256":"AB12","spki_sha256":"CD34","key":{"bits":384}},
            {"name":"Root B","issuer_sha256":"FF","sha256":"EF56","spki_sha256":"0078"}]"#;
        let bad = parse_advisory(json);
        assert_eq!(bad.len(), 2);
        assert_eq!(bad[0].sha256, "ab12");
        assert_eq!(bad[0].spki_sha256, "cd34");
        assert_eq!(bad[1].why, "eMudhra CA compromise advisory: Root B");
        assert!(bad[1].url.starts_with("https://"));
        let other = parse_advisory(r#"[{"name":"AAA","operator":"Sectigo","sha256":"1","spki_sha256":"2"},{"name":"X","sha256":"3","spki_sha256":"4"}]"#);
        assert!(other[0].why.contains("Sectigo root as a signer"));
        assert_eq!(other[1].why, "eMudhra CA compromise advisory: X");
        assert_eq!(bad[0].kind, "critical");
        assert_eq!(other[0].kind, "distrusted");
    }

    #[test]
    fn mozilla_csv_keeps_only_distrusted_roots() {
        let csv = "Common Name or Certificate Name,SHA-256 Fingerprint,Distrust for TLS After Date,Distrust for S/MIME After Date\n\
            \"Good, Root\",AA,,\nOld Root,BB,2024.11.30,\n";
        let bad = parse_mozilla(csv);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].sha256, "bb");
        assert!(bad[0].why.contains("2024.11.30"));
    }

    #[test]
    fn ccadb_removed_and_revoked_rows_become_bad_entries() {
        let removed = "Root Certificate Name,Firefox Release When Removed,SHA-256 Fingerprint,Removal Bug No. or Date\nOld,Firefox 117,AB,https://bugzilla.example/1\n";
        let bad = parse_removed(removed);
        assert_eq!(bad[0].sha256, "ab");
        assert!(bad[0].why.contains("Firefox 117"));
        assert_eq!(bad[0].url, "https://bugzilla.example/1");
        let revoked = "Revocation Status,RFC 5280 Revocation Reason Code,Date of Revocation,Certificate Subject Common Name,SHA-256 Fingerprint\nRevoked,(2) cACompromise,2023 Feb 24,Sub CA,CD\n";
        let bad = parse_revoked(revoked);
        assert_eq!(bad[0].kind, "critical");
        assert!(bad[0].why.contains("cACompromise"));
        let plain = "Revocation Status,RFC 5280 Revocation Reason Code,Date of Revocation,Certificate Subject Common Name,SHA-256 Fingerprint\nRevoked,(5) cessationOfOperation,2023 Feb 24,Sub CA,CD\n";
        assert_eq!(parse_revoked(plain)[0].kind, "revoked");
        assert!(bad[0].why.contains("2023 Feb 24"));
    }

    #[test]
    fn onecrl_pubkey_entries_become_revoked_by_spki() {
        let json = r#"{"data":[{"details":{"bug":"2083382"},"subject":"MDExGzAZBgNVBAMMEkVNIERWIFRMUyBDQSAtIEczQg==","pubKeyHash":"6+1kdcLC2A/LGZ8/6N1uazzmC3frFdTkLD3sDG9bUQU=","id":"a"},{"details":{"bug":"9"},"issuerName":"x","serialNumber":"y","id":"b"}]}"#;
        let bad = parse_onecrl(json);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].spki_sha256.len(), 64);
        assert!(bad[0].why.contains("EM DV TLS CA - G3B"));
        assert!(bad[0].url.ends_with("id=2083382"));
        assert_eq!(bad[0].kind, "revoked");
    }

    #[test]
    fn verdict_follows_list_then_dates() {
        let mut hit = crate::certs::scan(include_bytes!("../tests/fixtures/emsign-ecc-g3.der"))
            .remove(0);
        let none = Bads::default();
        assert!(matches!(judge(&hit, &none, now()), Verdict::Valid | Verdict::Expired(_)));
        let (from, to) = (hit.not_before.unwrap(), hit.not_after.unwrap());
        assert_eq!(judge(&hit, &none, from + 1), Verdict::Valid);
        assert!(matches!(judge(&hit, &none, to + 1), Verdict::Expired(_)));
        assert!(matches!(judge(&hit, &none, from - 1), Verdict::NotYetValid(_)));
        let bads = Bads {
            list: vec![Bad {
                sha256: crate::summary::hex(&hit.sha256),
                spki_sha256: String::new(),
                why: "x".into(),
                url: "https://example.test/".into(),
                kind: "distrusted".into(),
            }],
            source: "cache",
        };
        assert!(matches!(judge(&hit, &bads, from + 1), Verdict::Distrusted { .. }));
        hit.not_before = None;
        hit.not_after = None;
        assert_eq!(judge(&hit, &none, 0), Verdict::Unknown);
        assert_eq!(date(from), "2018-02-18");
    }
}
