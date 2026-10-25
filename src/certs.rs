/*
---
why: This file finds embedded certificates and trust anchors in a binary.
uses: bininfo
how: bininfo calls this file to scan read-only bytes.
The scan reads DER, PEM, bare base64, gzip, zlib, and zip.
The scan rejects BER indefinite length.
---
*/

//! Scan a byte slice for certificates, trust anchors, and pins.
//! A full certificate has an X.509 body, a signature algorithm, and a signature.
//! An anchor is a public key or trust-anchor info with a known key.
//! A body is a bare certificate body.
//! The scan reads DER, PEM, bare base64, gzip, zlib, and zip.
//! The scan rejects BER indefinite length.

mod inflate;
mod place;

use std::collections::HashMap;

/// One hit in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// File offset of the DER object or the encoded text.
    pub offset: usize,
    /// DER length includes the tag and the length bytes.
    /// PEM, base64, gzip, zlib, and zip length are that span.
    pub length: usize,
    /// Full certificate, trust anchor, bare body, or pin.
    pub kind: Kind,
    /// DER, PEM, or bare base64.
    pub encoding: Encoding,
    /// SHA-256 of the DER object.
    pub sha256: [u8; 32],
    /// SHA-256 of the public key.
    pub spki_sha256: [u8; 32],
    /// Subject common name. An anchor has none.
    pub subject_cn: Option<String>,
    /// Section name, segment name, overlay, header, or file.
    pub place: String,
    /// Trust material or a code-signature certificate.
    pub role: Role,
    /// File bytes, or the container that held the hit.
    pub container: Container,
    /// Start of validity, in Unix seconds. Only a certificate or a body has it.
    pub not_before: Option<i64>,
    /// End of validity, in Unix seconds.
    pub not_after: Option<i64>,
}

/// Full X.509 certificate, trust anchor, bare certificate body, or pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// The bytes have the X.509 certificate shape.
    Full,
    /// The bytes are a public key or trust-anchor info.
    Anchor,
    /// The bytes are a bare certificate body.
    Body,
    /// The bytes are a certificate pin or a key pin.
    Pin,
}

/// Trust material, or a certificate from a code signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// The hit is trust material.
    Trust,
    /// The hit is a signer certificate.
    Signer,
}

/// Container that held the hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Container {
    /// The hit is in the file bytes.
    File,
    /// The hit is inside a gzip member.
    Gzip,
    /// The hit is inside a zlib stream.
    Zlib,
    /// The hit is inside a zip entry.
    Zip,
    /// The hit is inside a Node SEA blob.
    Sea,
}

/// Wire form of one hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Encoding {
    /// Raw DER in the file.
    Der,
    /// A PEM certificate block.
    Pem,
    /// A bare base64 run.
    Base64,
}

/// Scan `bytes` for embedded certificates and trust anchors.
///
/// A DER hit starts at a canonical SEQUENCE tag.
/// The scan reads PEM, bare base64, gzip, zlib, and zip.
/// The scan reads the bytes inside a full certificate for a nested certificate.
/// The scan rejects BER indefinite length.
pub fn scan(bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    scan_raw(bytes, &mut hits);
    let mut budget = MAX_INFLATE_TOTAL;
    let stored = scan_zip(bytes, &mut hits, &mut budget);
    scan_gzip(bytes, &mut hits, &mut budget);
    scan_zlib(bytes, &mut hits, &mut budget);
    scan_utf16(bytes, &mut hits);
    scan_pins(bytes, &mut hits);
    tag_ranges(&stored, &mut hits, Container::Zip);
    let map = place::Map::build(bytes);
    for hit in &mut hits {
        hit.place = map.place(hit.offset);
        if map.signer(hit.offset) {
            hit.role = Role::Signer;
        }
        if hit.container == Container::File && map.sea(hit.offset) {
            hit.container = Container::Sea;
        }
    }
    sort_hits(&mut hits);
    hits
}

/// A segment or section of the file, by file offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub section: bool,
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

/// Name the segments and sections of an ELF, Mach-O, or PE file. Other bytes have none.
pub fn regions(bytes: &[u8]) -> Vec<Region> {
    let mut out: Vec<Region> = place::Map::build(bytes)
        .spans()
        .into_iter()
        .map(|(section, name, start, end)| Region {
            section,
            name,
            offset: start,
            size: end - start,
        })
        .collect();
    out.sort_by(|a, b| (a.offset, a.section, &a.name).cmp(&(b.offset, b.section, &b.name)));
    out
}

fn scan_raw(bytes: &[u8], hits: &mut Vec<Hit>) {
    let mut covered = Vec::new();
    scan_pem(bytes, hits, &mut covered);
    scan_b64(bytes, &mut covered, hits);
    scan_der(bytes, &covered, hits);
}

fn sort_hits(hits: &mut [Hit]) {
    hits.sort_by(|left, right| {
        left.offset
            .cmp(&right.offset)
            .then(left.length.cmp(&right.length))
            .then(left.sha256.cmp(&right.sha256))
            .then(left.kind.cmp(&right.kind))
            .then(left.encoding.cmp(&right.encoding))
            .then(left.container.cmp(&right.container))
            .then(left.role.cmp(&right.role))
            .then(left.place.cmp(&right.place))
            .then(left.subject_cn.cmp(&right.subject_cn))
    });
}

const MAX_CONTENT: usize = 1 << 20;
const MIN_OBJECT: usize = 44;
const MIN_B64: usize = 56;
const MAX_B64: usize = 256_000;
const MAX_PEM: usize = 2_000_000;
const MAX_DEPTH: usize = 8;
const MAX_INFLATE: usize = 1 << 20;
const MAX_INFLATE_TOTAL: usize = 4 << 20;
const MAX_STREAMS: usize = 16;
const MAX_ZIPS: usize = 8;
const MAX_ZIP_ENTRIES: usize = 64;
const MAX_PINS: usize = 64;
const MAX_PIN_EACH: usize = 8;
const MAX_UTF16: usize = 16;
const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const END: &[u8] = b"-----END CERTIFICATE-----";

const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const ED448: &[u8] = &[0x2b, 0x65, 0x71];
const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
const X448: &[u8] = &[0x2b, 0x65, 0x6f];
const CN_OID: &[u8] = &[0x55, 0x04, 0x03];

struct Found<'a> {
    kind: Kind,
    spki: &'a [u8],
    subject: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
struct Part {
    tag: u8,
    start: usize,
    head: usize,
    end: usize,
}

impl Part {
    const fn zero() -> Self {
        Self {
            tag: 0,
            start: 0,
            head: 0,
            end: 0,
        }
    }

    fn raw<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.start..self.end]
    }

    fn content<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.head..self.end]
    }
}

fn scan_pem(bytes: &[u8], hits: &mut Vec<Hit>, covered: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while from < bytes.len() {
        let Some(start) = find_slice(bytes, BEGIN, from) else {
            break;
        };
        let body = start + BEGIN.len();
        let Some(end_at) = find_slice(bytes, END, body) else {
            from = body;
            continue;
        };
        let finish = end_at + END.len();
        if end_at - body <= MAX_PEM {
            if let Some(der) = b64_decode(&bytes[body..end_at]) {
                let mut inner = Vec::new();
                walk(&der, 0, Encoding::Pem, false, 0, &mut inner);
                let span = finish - start;
                for hit in &mut inner {
                    hit.offset = start;
                    hit.length = span;
                }
                hits.extend(inner);
            }
        }
        covered.push((start, finish));
        from = finish;
    }
}

fn scan_b64(bytes: &[u8], covered: &mut Vec<(usize, usize)>, hits: &mut Vec<Hit>) {
    // Spans added below sit behind the cursor, so the snapshot stays right.
    let fixed = merged(covered);
    let mut index = 0;
    while index < bytes.len() {
        if let Some(end) = covered_end(index, &fixed) {
            index = end;
            continue;
        }
        if !is_b64(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        let mut too_long = false;
        while index < bytes.len() && is_b64(bytes[index]) && covered_end(index, &fixed).is_none() {
            index += 1;
            if index - start > MAX_B64 {
                too_long = true;
                break;
            }
        }
        if too_long {
            while index < bytes.len() && (is_b64(bytes[index]) || bytes[index] == b'=') {
                index += 1;
            }
            continue;
        }
        let mut end = index;
        let mut pads = 0;
        while end < bytes.len()
            && pads < 2
            && bytes[end] == b'='
            && end - start <= MAX_B64
            && covered_end(end, &fixed).is_none()
        {
            end += 1;
            pads += 1;
        }
        let run = end - start;
        if run >= MIN_B64 && run % 4 == 0 {
            if let Some(der) = b64_decode(&bytes[start..end]) {
                let mut inner = Vec::new();
                walk(&der, 0, Encoding::Base64, false, 0, &mut inner);
                let covers = inner
                    .iter()
                    .any(|hit| hit.offset == 0 && hit.length == der.len());
                if covers {
                    let span = end - start;
                    for hit in &mut inner {
                        hit.offset = start;
                        hit.length = span;
                    }
                    hits.extend(inner);
                    covered.push((start, end));
                }
            }
        }
        if end == start {
            index = start + 1;
        } else {
            index = end;
        }
    }
}

fn scan_der(bytes: &[u8], covered: &[(usize, usize)], hits: &mut Vec<Hit>) {
    let mut spans = covered.to_vec();
    spans.sort_unstable();
    let mut cursor = 0;
    for (start, end) in spans {
        if cursor >= bytes.len() {
            break;
        }
        let start = start.min(bytes.len());
        if start > cursor {
            walk(&bytes[cursor..start], cursor, Encoding::Der, false, 0, hits);
        }
        cursor = cursor.max(end);
    }
    if cursor < bytes.len() {
        walk(&bytes[cursor..], cursor, Encoding::Der, false, 0, hits);
    }
}

fn walk(
    bytes: &[u8],
    base: usize,
    encoding: Encoding,
    nested_only: bool,
    depth: usize,
    hits: &mut Vec<Hit>,
) {
    let mut index = 0;
    while index < bytes.len() {
        let Some(total) = sequence_total(bytes, index) else {
            if !nested_only {
                if let Some(span) = unwrapped_spki(bytes, index) {
                    let content = &bytes[index..index + span];
                    let wrapped = wrap_sequence(content);
                    let digest = sha256(&wrapped);
                    hits.push(Hit {
                        offset: base + index,
                        length: span,
                        kind: Kind::Anchor,
                        encoding,
                        sha256: digest,
                        spki_sha256: digest,
                        subject_cn: None,
                        place: String::new(),
                        role: Role::Trust,
                        container: Container::File,
                        not_before: None,
                        not_after: None,
                    });
                    index += span;
                    continue;
                }
            }
            index += 1;
            continue;
        };
        let slice = &bytes[index..index + total];
        if let Some(found) = classify(slice) {
            let record = !nested_only || found.kind == Kind::Full;
            if record {
                hits.push(hit_from(base + index, total, encoding, slice, &found));
            }
            let dive = record && matches!(found.kind, Kind::Full | Kind::Body) && depth < MAX_DEPTH;
            if dive {
                if let Some(header) = header_len(slice) {
                    if header < slice.len() {
                        walk(
                            &slice[header..],
                            base + index + header,
                            encoding,
                            true,
                            depth + 1,
                            hits,
                        );
                    }
                }
            }
            if record {
                index += total;
                continue;
            }
        }
        index += 1;
    }
}

fn hit_from(
    offset: usize,
    length: usize,
    encoding: Encoding,
    der: &[u8],
    found: &Found<'_>,
) -> Hit {
    let dates = validity_of(der, found.kind);
    Hit {
        offset,
        length,
        kind: found.kind,
        encoding,
        sha256: sha256(der),
        spki_sha256: sha256(found.spki),
        subject_cn: found.subject.and_then(subject_cn),
        place: String::new(),
        role: Role::Trust,
        container: Container::File,
        not_before: dates.map(|d| d.0),
        not_after: dates.map(|d| d.1),
    }
}

fn merged(spans: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut sorted = spans.to_vec();
    sorted.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

// `covered` is sorted and disjoint.
fn covered_end(index: usize, covered: &[(usize, usize)]) -> Option<usize> {
    let next = covered.partition_point(|span| span.0 <= index);
    let (_, end) = *covered.get(next.checked_sub(1)?)?;
    (index < end).then_some(end)
}

fn find_slice(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() || hay.len() - from < needle.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|index| index + from)
}

fn is_b64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

fn push_decoded(
    data: &[u8],
    offset: usize,
    length: usize,
    container: Container,
    hits: &mut Vec<Hit>,
) {
    let mut inner = Vec::new();
    scan_raw(data, &mut inner);
    for hit in &mut inner {
        hit.offset = offset;
        hit.length = length;
        hit.container = container;
    }
    hits.extend(inner);
}

fn take_budget(budget: &mut usize, size: usize) -> bool {
    if size > *budget {
        return false;
    }
    *budget -= size;
    true
}

fn scan_gzip(bytes: &[u8], hits: &mut Vec<Hit>, budget: &mut usize) {
    let mut from = 0;
    let mut attempts = 0;
    while attempts < MAX_STREAMS {
        let Some(at) = find_slice(bytes, &[0x1f, 0x8b], from) else {
            break;
        };
        from = at + 1;
        let Some((data, member)) = inflate::gunzip(&bytes[at..], MAX_INFLATE) else {
            continue;
        };
        attempts += 1;
        from = at + member.max(1);
        if data.is_empty() {
            continue;
        }
        if !take_budget(budget, data.len()) {
            break;
        }
        let before = hits.len();
        push_decoded(&data, at, member, Container::Gzip, hits);
        if hits.len() > before {
            hide_file_hits(hits, at, at + member);
        }
    }
}

fn scan_zlib(bytes: &[u8], hits: &mut Vec<Hit>, budget: &mut usize) {
    let mut index = 0;
    let mut attempts = 0;
    while attempts < MAX_STREAMS && index + 2 < bytes.len() {
        if bytes[index] != 0x78 {
            index += 1;
            continue;
        }
        let flg = bytes[index + 1];
        let check = u16::from(bytes[index]) * 256 + u16::from(flg);
        if check % 31 != 0 || flg & 0x20 != 0 || bytes[index] & 0x0f != 8 {
            index += 1;
            continue;
        }
        let Some(head) = inflate::prefix(&bytes[index + 2..], 8) else {
            index += 1;
            continue;
        };
        if !certish(&head) {
            index += 1;
            continue;
        }
        let at = index;
        let Some((data, used)) = inflate::unzlib(&bytes[at..], MAX_INFLATE) else {
            index += 1;
            continue;
        };
        attempts += 1;
        index = at + used.max(1);
        if data.is_empty() {
            continue;
        }
        if !take_budget(budget, data.len()) {
            break;
        }
        let before = hits.len();
        push_decoded(&data, at, used, Container::Zlib, hits);
        if hits.len() > before {
            hide_file_hits(hits, at, at + used);
        }
    }
}

fn certish(prefix: &[u8]) -> bool {
    if prefix.starts_with(b"-----BEGIN ") || prefix.starts_with(b"PK\x03\x04") {
        return true;
    }
    prefix.len() >= 2
        && prefix[0] == 0x30
        && (prefix[1] < 0x80 || matches!(prefix[1], 0x81 | 0x82 | 0x83))
}

fn scan_zip(bytes: &[u8], hits: &mut Vec<Hit>, budget: &mut usize) -> Vec<(usize, usize)> {
    let mut stored = Vec::new();
    let mut from = 0;
    let mut zips = 0;
    while zips < MAX_ZIPS {
        let Some(at) = find_slice(bytes, b"PK\x05\x06", from) else {
            break;
        };
        from = at + 1;
        let Some(entries) = zip_entries(bytes, at) else {
            continue;
        };
        zips += 1;
        let mut count = 0;
        for entry in entries {
            if count >= MAX_ZIP_ENTRIES {
                break;
            }
            count += 1;
            if entry.method == 0 {
                let Some(slice) = bytes.get(entry.data..entry.data + entry.comp) else {
                    continue;
                };
                if entry.plain != entry.comp || inflate::crc32(slice) != entry.crc {
                    continue;
                }
                stored.push((entry.data, entry.data + entry.comp));
                continue;
            }
            if entry.method != 8 {
                continue;
            }
            let Some(slice) = bytes.get(entry.data..entry.data + entry.comp) else {
                continue;
            };
            let cap = if entry.plain == 0 {
                MAX_INFLATE
            } else {
                MAX_INFLATE.min(entry.plain)
            };
            let Some((data, _)) = inflate::raw(slice, cap) else {
                continue;
            };
            if entry.plain != 0 && data.len() != entry.plain {
                continue;
            }
            if inflate::crc32(&data) != entry.crc {
                continue;
            }
            if !take_budget(budget, data.len()) {
                return stored;
            }
            let end = entry.data + entry.comp;
            push_decoded(&data, entry.data, entry.comp, Container::Zip, hits);
            hits.retain(|hit| {
                !(hit.container == Container::File && hit.offset >= entry.data && hit.offset < end)
            });
        }
    }
    stored
}

struct ZipEntry {
    method: u16,
    crc: u32,
    comp: usize,
    plain: usize,
    data: usize,
}

fn zip_entries(bytes: &[u8], eocd: usize) -> Option<Vec<ZipEntry>> {
    if eocd + 22 > bytes.len() {
        return None;
    }
    let comment = u16::from_le_bytes([bytes[eocd + 20], bytes[eocd + 21]]) as usize;
    if eocd + 22 + comment > bytes.len() {
        return None;
    }
    let total = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
    let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().ok()?) as usize;
    let cd_off = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().ok()?) as usize;
    if cd_size == 0xffff_ffff || cd_off == 0xffff_ffff || total == 0xffff {
        return None;
    }
    let base = zip_base(bytes, eocd, cd_off, cd_size)?;
    let cd_at = base.checked_add(cd_off)?;
    let cd_end = cd_at.checked_add(cd_size)?;
    if cd_end > bytes.len() || bytes.get(cd_at..cd_at + 4) != Some(b"PK\x01\x02") {
        return None;
    }
    let mut entries = Vec::new();
    let mut at = cd_at;
    let stop = total.min(MAX_ZIP_ENTRIES);
    while entries.len() < stop && at + 46 <= cd_end {
        if bytes.get(at..at + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let flags = u16::from_le_bytes([bytes[at + 8], bytes[at + 9]]);
        let method = u16::from_le_bytes([bytes[at + 10], bytes[at + 11]]);
        let crc = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().ok()?);
        let comp = u32::from_le_bytes(bytes[at + 20..at + 24].try_into().ok()?) as usize;
        let plain = u32::from_le_bytes(bytes[at + 24..at + 28].try_into().ok()?) as usize;
        let name = u16::from_le_bytes([bytes[at + 28], bytes[at + 29]]) as usize;
        let extra = u16::from_le_bytes([bytes[at + 30], bytes[at + 31]]) as usize;
        let note = u16::from_le_bytes([bytes[at + 32], bytes[at + 33]]) as usize;
        let local = u32::from_le_bytes(bytes[at + 42..at + 46].try_into().ok()?) as usize;
        let Some(next) = at
            .checked_add(46)
            .and_then(|pos| pos.checked_add(name))
            .and_then(|pos| pos.checked_add(extra))
            .and_then(|pos| pos.checked_add(note))
        else {
            break;
        };
        if next > cd_end {
            break;
        }
        at = next;
        if flags & 1 != 0 || comp == 0xffff_ffff || plain == 0xffff_ffff {
            continue;
        }
        if comp == 0 && plain == 0 {
            continue;
        }
        if flags & 8 != 0 && comp == 0 {
            continue;
        }
        let Some(data) = zip_data(bytes, base.saturating_add(local)) else {
            continue;
        };
        if data.saturating_add(comp) > bytes.len() {
            continue;
        }
        entries.push(ZipEntry {
            method,
            crc,
            comp,
            plain,
            data,
        });
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

fn zip_base(bytes: &[u8], eocd: usize, cd_off: usize, cd_size: usize) -> Option<usize> {
    if bytes.get(cd_off..cd_off + 4) == Some(b"PK\x01\x02") {
        return Some(0);
    }
    let base = eocd.checked_sub(cd_size)?.checked_sub(cd_off)?;
    if bytes.get(base + cd_off..base + cd_off + 4) == Some(b"PK\x01\x02") {
        Some(base)
    } else {
        None
    }
}

fn zip_data(bytes: &[u8], local: usize) -> Option<usize> {
    if local.checked_add(30)? > bytes.len() || bytes.get(local..local + 4) != Some(b"PK\x03\x04") {
        return None;
    }
    let name = u16::from_le_bytes([bytes[local + 26], bytes[local + 27]]) as usize;
    let extra = u16::from_le_bytes([bytes[local + 28], bytes[local + 29]]) as usize;
    if name > 4096 {
        return None;
    }
    local.checked_add(30)?.checked_add(name)?.checked_add(extra)
}

fn hide_file_hits(hits: &mut Vec<Hit>, start: usize, end: usize) {
    hits.retain(|hit| hit.container != Container::File || hit.offset < start || hit.offset >= end);
}

fn tag_ranges(ranges: &[(usize, usize)], hits: &mut [Hit], container: Container) {
    for hit in hits {
        if hit.container != Container::File {
            continue;
        }
        if ranges
            .iter()
            .any(|(start, end)| hit.offset >= *start && hit.offset < *end)
        {
            hit.container = container;
        }
    }
}

fn scan_utf16(bytes: &[u8], hits: &mut Vec<Hit>) {
    let begin = utf16_ascii(b"-----BEGIN CERTIFICATE-----");
    let end = utf16_ascii(b"-----END CERTIFICATE-----");
    let mut from = 0;
    let mut found = 0;
    while found < MAX_UTF16 {
        let Some(start) = find_slice(bytes, &begin, from) else {
            break;
        };
        let body = start + begin.len();
        let Some(end_at) = find_slice(bytes, &end, body) else {
            from = body;
            continue;
        };
        let finish = end_at + end.len();
        from = finish;
        if finish - start > MAX_PEM || (finish - start) % 2 != 0 {
            continue;
        }
        let wide = &bytes[start..finish];
        if wide.chunks(2).any(|pair| pair.len() == 2 && pair[1] != 0) {
            continue;
        }
        let text: Vec<u8> = wide.iter().step_by(2).copied().collect();
        let before = hits.len();
        let mut inner = Vec::new();
        scan_raw(&text, &mut inner);
        for hit in &mut inner {
            hit.offset = start;
            hit.length = finish - start;
        }
        if inner.is_empty() {
            continue;
        }
        hits.extend(inner);
        if hits.len() > before {
            found += 1;
        }
    }
}

fn utf16_ascii(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for &byte in text {
        out.push(byte);
        out.push(0);
    }
    out
}

fn scan_pins(bytes: &[u8], hits: &mut Vec<Hit>) {
    let mut digests: HashMap<[u8; 32], Option<String>> = HashMap::new();
    for hit in hits.iter() {
        if hit.kind == Kind::Pin {
            continue;
        }
        let cn = hit.subject_cn.clone();
        digests.entry(hit.sha256).or_insert_with(|| cn.clone());
        digests.entry(hit.spki_sha256).or_insert(cn);
    }
    pin_text(bytes, &digests, hits);
    pin_raw(bytes, &digests, hits);
}

fn pin_text(bytes: &[u8], digests: &HashMap<[u8; 32], Option<String>>, hits: &mut Vec<Hit>) {
    let mut from = 0;
    let mut count = hits.iter().filter(|hit| hit.kind == Kind::Pin).count();
    while count < MAX_PINS {
        let Some(at) = find_slice(bytes, b"sha256/", from) else {
            break;
        };
        from = at + 1;
        let start = at + b"sha256/".len();
        let mut end = start;
        while end < bytes.len() && end - start < 44 && is_b64(bytes[end]) {
            end += 1;
        }
        if end < bytes.len() && bytes[end] == b'=' && end - start == 43 {
            end += 1;
        }
        let token = &bytes[start..end];
        if token.len() != 43 && token.len() != 44 {
            continue;
        }
        let Some(raw) = b64_decode(token) else {
            continue;
        };
        if raw.len() != 32 {
            continue;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&raw);
        let cn = digests.get(&hash).and_then(Clone::clone);
        hits.push(pin_hit(at, end - at, Encoding::Base64, hash, cn));
        count += 1;
        from = end;
    }
}

fn pin_raw(bytes: &[u8], digests: &HashMap<[u8; 32], Option<String>>, hits: &mut Vec<Hit>) {
    if digests.is_empty() || bytes.len() < 32 {
        return;
    }
    let mut heads: HashMap<[u8; 8], Vec<[u8; 32]>> = HashMap::new();
    for hash in digests.keys() {
        let mut head = [0u8; 8];
        head.copy_from_slice(&hash[..8]);
        heads.entry(head).or_default().push(*hash);
    }
    // Two leading bytes rule out nearly every offset before any hashing.
    let mut seen_pair = vec![false; 1 << 16];
    for hash in digests.keys() {
        seen_pair[usize::from(hash[0]) << 8 | usize::from(hash[1])] = true;
    }
    let mut per: HashMap<[u8; 32], usize> = HashMap::new();
    let mut count = hits.iter().filter(|hit| hit.kind == Kind::Pin).count();
    let mut index = 0;
    while count < MAX_PINS && index + 32 <= bytes.len() {
        if !seen_pair[usize::from(bytes[index]) << 8 | usize::from(bytes[index + 1])] {
            index += 1;
            continue;
        }
        let mut head = [0u8; 8];
        head.copy_from_slice(&bytes[index..index + 8]);
        let Some(cands) = heads.get(&head) else {
            index += 1;
            continue;
        };
        let mut matched = false;
        for cand in cands {
            if &bytes[index..index + 32] != cand {
                continue;
            }
            let seen = per.get(cand).copied().unwrap_or(0);
            if seen >= MAX_PIN_EACH || inside_cert(index, 32, hits) {
                break;
            }
            let cn = digests.get(cand).and_then(Clone::clone);
            hits.push(pin_hit(index, 32, Encoding::Der, *cand, cn));
            per.insert(*cand, seen + 1);
            count += 1;
            matched = true;
            break;
        }
        index += if matched { 32 } else { 1 };
    }
}

fn inside_cert(offset: usize, length: usize, hits: &[Hit]) -> bool {
    let end = offset.saturating_add(length);
    hits.iter().any(|hit| {
        hit.kind != Kind::Pin
            && offset >= hit.offset
            && end <= hit.offset.saturating_add(hit.length)
    })
}

fn pin_hit(
    offset: usize,
    length: usize,
    encoding: Encoding,
    hash: [u8; 32],
    subject_cn: Option<String>,
) -> Hit {
    Hit {
        offset,
        length,
        kind: Kind::Pin,
        encoding,
        sha256: hash,
        spki_sha256: hash,
        subject_cn,
        place: String::new(),
        role: Role::Trust,
        container: Container::File,
        not_before: None,
        not_after: None,
    }
}

// Some trust anchors omit the outer SEQUENCE tag.
fn unwrapped_spki(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&0x30) {
        return None;
    }
    let (tag, _, alg_end) = next_part(bytes, index)?;
    if tag != 0x30 || alg_end.saturating_sub(index) > 40 {
        return None;
    }
    if bytes.get(alg_end) != Some(&0x03) {
        return None;
    }
    let (bit_tag, _, end) = next_part(bytes, alg_end)?;
    if bit_tag != 0x03 || end <= index {
        return None;
    }
    let content = &bytes[index..end];
    let mut kids = [Part::zero(); 4];
    let count = fill(content, &mut kids)?;
    if !spki_parts_ok(content, &kids[..count]) {
        return None;
    }
    Some(end - index)
}

fn wrap_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(0x30);
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xff {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xffff {
        out.push(0x82);
        out.extend_from_slice(&u16::try_from(len).unwrap_or(0).to_be_bytes());
    } else {
        out.push(0x83);
        let be = u32::try_from(len).unwrap_or(0).to_be_bytes();
        out.extend_from_slice(&be[1..]);
    }
    out.extend_from_slice(content);
    out
}

fn sequence_total(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&0x30) {
        return None;
    }
    let (content_len, len_bytes) = der_len(bytes.get(index + 1..)?)?;
    let header = len_bytes.checked_add(1)?;
    let total = header.checked_add(content_len)?;
    if total < MIN_OBJECT {
        return None;
    }
    let end = index.checked_add(total)?;
    if end > bytes.len() {
        return None;
    }
    let first = *bytes.get(index + header)?;
    if first != 0x30 && first != 0xa0 && first != 0x02 {
        return None;
    }
    Some(total)
}

fn header_len(slice: &[u8]) -> Option<usize> {
    let (_, len_bytes) = der_len(slice.get(1..)?)?;
    Some(len_bytes + 1)
}

fn classify(slice: &[u8]) -> Option<Found<'_>> {
    let (tag, head, end) = next_part(slice, 0)?;
    if tag != 0x30 || end != slice.len() {
        return None;
    }
    let body = &slice[head..end];
    let first = *body.first()?;
    if first != 0x30 && first != 0xa0 && first != 0x02 {
        return None;
    }
    let mut kids = [Part::zero(); 16];
    let count = fill(body, &mut kids)?;
    let kids = &kids[..count];
    if let Some(found) = as_cert(body, kids) {
        return Some(found);
    }
    if let Some(found) = as_spki(body, kids, slice) {
        return Some(found);
    }
    if let Some(found) = as_tai(body, kids) {
        return Some(found);
    }
    as_body(body, kids)
}

fn as_cert<'a>(body: &'a [u8], kids: &[Part]) -> Option<Found<'a>> {
    if kids.len() != 3 || kids[0].tag != 0x30 || kids[1].tag != 0x30 || kids[2].tag != 0x03 {
        return None;
    }
    if !alg_ok(kids[1].content(body)) || !bit_ok(kids[2].content(body)) {
        return None;
    }
    let tbs = kids[0].content(body);
    let mut fields = [Part::zero(); 16];
    let count = fill(tbs, &mut fields)?;
    let (spki, subject) = tbs_pair(tbs, &fields[..count], Some(kids[1].content(body)))?;
    Some(Found {
        kind: Kind::Full,
        spki,
        subject: Some(subject),
    })
}

fn as_spki<'a>(body: &'a [u8], kids: &[Part], whole: &'a [u8]) -> Option<Found<'a>> {
    if !spki_parts_ok(body, kids) {
        return None;
    }
    Some(Found {
        kind: Kind::Anchor,
        spki: whole,
        subject: None,
    })
}

fn as_tai<'a>(body: &'a [u8], kids: &[Part]) -> Option<Found<'a>> {
    let mut index = 0;
    if kids.first().map(|part| part.tag) == Some(0x02) {
        if !version_one(kids[0].content(body)) {
            return None;
        }
        index = 1;
    }
    if index >= kids.len() || kids[index].tag != 0x30 {
        return None;
    }
    let spki = kids[index].raw(body);
    if !spki_ok(spki) {
        return None;
    }
    index += 1;
    if index < kids.len() {
        let id = kids[index];
        if kids.len() != index + 1 || id.tag != 0x04 {
            return None;
        }
        let len = id.end.saturating_sub(id.head);
        if !(1..=64).contains(&len) {
            return None;
        }
    }
    Some(Found {
        kind: Kind::Anchor,
        spki,
        subject: None,
    })
}

fn as_body<'a>(body: &'a [u8], kids: &[Part]) -> Option<Found<'a>> {
    let (spki, subject) = tbs_pair(body, kids, None)?;
    Some(Found {
        kind: Kind::Body,
        spki,
        subject: Some(subject),
    })
}

fn tbs_pair<'a>(
    bytes: &'a [u8],
    fields: &[Part],
    signature: Option<&[u8]>,
) -> Option<(&'a [u8], &'a [u8])> {
    let mut rest = fields;
    if let Some(first) = rest.first() {
        if first.tag == 0xa0 {
            if !version_ok(first.content(bytes)) {
                return None;
            }
            rest = &rest[1..];
        }
    }
    if rest.len() < 6 {
        return None;
    }
    if rest[0].tag != 0x02 || !serial_ok(rest[0].content(bytes)) {
        return None;
    }
    if rest[1].tag != 0x30 || !alg_ok(rest[1].content(bytes)) {
        return None;
    }
    if let Some(signature) = signature {
        if rest[1].content(bytes) != signature {
            return None;
        }
    }
    if rest[2].tag != 0x30 || !name_ok(rest[2].content(bytes)) {
        return None;
    }
    if rest[3].tag != 0x30 || !validity_ok(rest[3].content(bytes)) {
        return None;
    }
    if rest[4].tag != 0x30 || !name_ok(rest[4].content(bytes)) {
        return None;
    }
    if rest[5].tag != 0x30 || !spki_ok(rest[5].raw(bytes)) {
        return None;
    }
    if !rest[6..].iter().all(|field| field.tag & 0xc0 == 0x80) {
        return None;
    }
    Some((rest[5].raw(bytes), rest[4].content(bytes)))
}

fn spki_ok(bytes: &[u8]) -> bool {
    let Some((tag, head, end)) = next_part(bytes, 0) else {
        return false;
    };
    if tag != 0x30 || end != bytes.len() {
        return false;
    }
    let mut kids = [Part::zero(); 4];
    let Some(count) = fill(&bytes[head..end], &mut kids) else {
        return false;
    };
    spki_parts_ok(&bytes[head..end], &kids[..count])
}

fn spki_parts_ok(body: &[u8], kids: &[Part]) -> bool {
    if kids.len() != 2 || kids[0].tag != 0x30 || kids[1].tag != 0x03 {
        return false;
    }
    let alg = kids[0].content(body);
    let bits = kids[1].content(body);
    let mut fields = [Part::zero(); 4];
    let Some(count) = fill(alg, &mut fields) else {
        return false;
    };
    let fields = &fields[..count];
    if fields.is_empty() || fields[0].tag != 0x06 || !oid_ok(fields[0].content(alg)) {
        return false;
    }
    let oid = fields[0].content(alg);
    if oid == RSA {
        return fields.len() == 2 && fields[1].raw(alg) == [0x05, 0x00] && rsa_ok(bits);
    }
    if oid == EC {
        return fields.len() == 2 && fields[1].tag == 0x06 && ec_ok(fields[1].content(alg), bits);
    }
    if fields.len() != 1 {
        return false;
    }
    if oid == ED25519 {
        return raw_len(bits, 32);
    }
    if oid == ED448 {
        return raw_len(bits, 57);
    }
    if oid == X25519 {
        return raw_len(bits, 32);
    }
    if oid == X448 {
        return raw_len(bits, 56);
    }
    false
}

fn rsa_ok(bits: &[u8]) -> bool {
    let Some((&0, payload)) = bits.split_first() else {
        return false;
    };
    let mut wrap = [Part::zero(); 2];
    let Some(count) = fill(payload, &mut wrap) else {
        return false;
    };
    if count != 1 || wrap[0].tag != 0x30 {
        return false;
    }
    let seq = wrap[0].content(payload);
    let mut kids = [Part::zero(); 4];
    let Some(count) = fill(seq, &mut kids) else {
        return false;
    };
    let kids = &kids[..count];
    if kids.len() != 2 || kids[0].tag != 0x02 || kids[1].tag != 0x02 {
        return false;
    }
    let modulus = kids[0].content(seq);
    let exponent = kids[1].content(seq);
    if !integer_ok(modulus) || !integer_ok(exponent) {
        return false;
    }
    let mut mod_len = modulus.len();
    if modulus.first() == Some(&0x00) {
        mod_len -= 1;
    }
    (64..=1024).contains(&mod_len) && (1..=8).contains(&exponent.len())
}

fn ec_ok(curve: &[u8], bits: &[u8]) -> bool {
    let coord = if curve == P256 {
        32
    } else if curve == P384 {
        48
    } else if curve == P521 {
        66
    } else {
        return false;
    };
    let Some((&0, point)) = bits.split_first() else {
        return false;
    };
    if point.is_empty() {
        return false;
    }
    match point[0] {
        0x04 => point.len() == 1 + coord + coord,
        0x02 | 0x03 => point.len() == 1 + coord,
        _ => false,
    }
}

fn raw_len(bits: &[u8], len: usize) -> bool {
    matches!(bits.split_first(), Some((&0, key)) if key.len() == len)
}

fn version_ok(content: &[u8]) -> bool {
    let mut kids = [Part::zero(); 2];
    let Some(count) = fill(content, &mut kids) else {
        return false;
    };
    let kids = &kids[..count];
    kids.len() == 1
        && kids[0].tag == 0x02
        && integer_ok(kids[0].content(content))
        && matches!(unsigned(kids[0].content(content)), Some(0..=2))
}

fn version_one(content: &[u8]) -> bool {
    integer_ok(content) && unsigned(content) == Some(1)
}

fn serial_ok(content: &[u8]) -> bool {
    !content.is_empty() && content.len() <= 20 && content[0] & 0x80 == 0 && integer_ok(content)
}

fn integer_ok(content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }
    if content.len() == 1 {
        return true;
    }
    if content[0] == 0x00 && content[1] & 0x80 == 0 {
        return false;
    }
    content[0] != 0xff || content[1] & 0x80 == 0
}

fn unsigned(content: &[u8]) -> Option<u32> {
    if content.is_empty() || content.len() > 4 || content[0] & 0x80 != 0 {
        return None;
    }
    let mut value = 0u32;
    for byte in content {
        value = (value << 8) | u32::from(*byte);
    }
    Some(value)
}

fn alg_ok(content: &[u8]) -> bool {
    let mut kids = [Part::zero(); 4];
    let Some(count) = fill(content, &mut kids) else {
        return false;
    };
    let kids = &kids[..count];
    if kids.is_empty() || kids.len() > 2 || kids[0].tag != 0x06 {
        return false;
    }
    oid_ok(kids[0].content(content))
}

fn oid_ok(content: &[u8]) -> bool {
    if content.is_empty() || content.len() > 32 {
        return false;
    }
    let mut index = 0;
    while index < content.len() {
        if content[index] == 0x80 {
            return false;
        }
        while index < content.len() && content[index] & 0x80 != 0 {
            index += 1;
        }
        if index >= content.len() {
            return false;
        }
        index += 1;
    }
    true
}

fn name_ok(content: &[u8]) -> bool {
    let mut index = 0;
    while index < content.len() {
        let Some((tag, _, end)) = next_part(content, index) else {
            return false;
        };
        if tag != 0x31 || end <= index {
            return false;
        }
        index = end;
    }
    true
}

// Read notBefore and notAfter from a certificate or a bare body.
fn validity_of(der: &[u8], kind: Kind) -> Option<(i64, i64)> {
    let (_, head, end) = next_part(der, 0)?;
    let body = &der[head..end];
    let mut kids = [Part::zero(); 16];
    let count = fill(body, &mut kids)?;
    let tbs_part = match kind {
        Kind::Full => kids[0],
        Kind::Body => Part {
            tag: 0x30,
            start: 0,
            head: 0,
            end: body.len(),
        },
        _ => return None,
    };
    let tbs = tbs_part.content(body);
    let mut fields = [Part::zero(); 16];
    let n = if kind == Kind::Full {
        fill(tbs, &mut fields)?
    } else {
        for (slot, kid) in fields.iter_mut().zip(&kids[..count]) {
            *slot = *kid;
        }
        count
    };
    let mut rest = &fields[..n];
    if rest.first()?.tag == 0xa0 {
        rest = &rest[1..];
    }
    let src = if kind == Kind::Full { tbs } else { body };
    let mut times = [Part::zero(); 4];
    let count = fill(rest.get(3)?.content(src), &mut times)?;
    if count != 2 {
        return None;
    }
    let window = rest[3].content(src);
    Some((
        unix_time(times[0].tag, times[0].content(window))?,
        unix_time(times[1].tag, times[1].content(window))?,
    ))
}

// UTCTime and GeneralizedTime to Unix seconds. A zone offset is applied.
fn unix_time(tag: u8, text: &[u8]) -> Option<i64> {
    let (year_len, digits) = if tag == 0x17 { (2, 12) } else { (4, 14) };
    let num = |from: usize, len: usize| -> Option<i64> {
        std::str::from_utf8(text.get(from..from + len)?)
            .ok()?
            .parse()
            .ok()
    };
    let mut year = num(0, year_len)?;
    if tag == 0x17 {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let at = year_len;
    let (month, day, hour, min, sec) = (
        num(at, 2)?,
        num(at + 2, 2)?,
        num(at + 4, 2)?,
        num(at + 6, 2)?,
        num(at + 8, 2)?,
    );
    let mut secs = days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec;
    if text.len() == digits + 5 {
        let off = num(digits + 1, 2)? * 3600 + num(digits + 3, 2)? * 60;
        secs += if text[digits] == b'+' { -off } else { off };
    }
    Some(secs)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn validity_ok(content: &[u8]) -> bool {
    let mut kids = [Part::zero(); 4];
    let Some(count) = fill(content, &mut kids) else {
        return false;
    };
    let kids = &kids[..count];
    kids.len() == 2
        && kids
            .iter()
            .all(|field| time_ok(field.tag, field.content(content)))
}

fn time_ok(tag: u8, content: &[u8]) -> bool {
    let digits = match tag {
        0x17 => 12,
        0x18 => 14,
        _ => return false,
    };
    if content.len() == digits + 1 && content[digits] == b'Z' {
        return content[..digits].iter().all(u8::is_ascii_digit);
    }
    if content.len() == digits + 5 && (content[digits] == b'+' || content[digits] == b'-') {
        return content[..digits].iter().all(u8::is_ascii_digit)
            && content[digits + 1..].iter().all(u8::is_ascii_digit);
    }
    false
}

fn bit_ok(content: &[u8]) -> bool {
    matches!(content.split_first(), Some((&0, payload)) if payload.len() >= 8)
}

fn subject_cn(name: &[u8]) -> Option<String> {
    let mut index = 0;
    while index < name.len() {
        let (tag, head, end) = next_part(name, index)?;
        if tag != 0x31 || end <= index {
            return None;
        }
        let set = &name[head..end];
        let mut at = 0;
        while at < set.len() {
            let (tag, at_head, at_end) = next_part(set, at)?;
            if at_end <= at {
                return None;
            }
            if tag == 0x30 {
                if let Some(text) = atv_cn(&set[at_head..at_end]) {
                    return Some(text);
                }
            }
            at = at_end;
        }
        index = end;
    }
    None
}

fn atv_cn(atv: &[u8]) -> Option<String> {
    let (tag, _, next) = next_part(atv, 0)?;
    if tag != 0x06 {
        return None;
    }
    let (_, oid_head, oid_end) = next_part(atv, 0)?;
    if &atv[oid_head..oid_end] != CN_OID {
        return None;
    }
    let (value_tag, value_head, value_end) = next_part(atv, next)?;
    decode_string(value_tag, &atv[value_head..value_end])
}

fn decode_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        0x0c | 0x13 | 0x14 | 0x16 => Some(String::from_utf8_lossy(value).into_owned()),
        0x1e => decode_bmp(value),
        _ => None,
    }
}

fn decode_bmp(value: &[u8]) -> Option<String> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(value.len() / 2);
    for pair in value.chunks_exact(2) {
        units.push(u16::from_be_bytes([pair[0], pair[1]]));
    }
    Some(String::from_utf16_lossy(&units))
}

fn fill(bytes: &[u8], out: &mut [Part]) -> Option<usize> {
    let mut index = 0;
    let mut count = 0;
    while index < bytes.len() {
        if count >= out.len() {
            return None;
        }
        let (tag, head, end) = next_part(bytes, index)?;
        if end <= index {
            return None;
        }
        out[count] = Part {
            tag,
            start: index,
            head,
            end,
        };
        count += 1;
        index = end;
    }
    Some(count)
}

fn next_part(bytes: &[u8], index: usize) -> Option<(u8, usize, usize)> {
    if index >= bytes.len() {
        return None;
    }
    let tag = bytes[index];
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (content_len, len_bytes) = der_len(bytes.get(index + 1..)?)?;
    let header = len_bytes.checked_add(1)?;
    let total = header.checked_add(content_len)?;
    let end = index.checked_add(total)?;
    if end > bytes.len() {
        return None;
    }
    Some((tag, index + header, end))
}

fn der_len(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    // BER indefinite length is not DER.
    if first == 0x80 {
        return None;
    }
    let width = usize::from(first & 0x7f);
    if width == 0 || width > 3 || bytes.len() < 1 + width {
        return None;
    }
    let mut value = 0usize;
    for byte in &bytes[1..1 + width] {
        value = value.checked_shl(8)?.checked_add(usize::from(*byte))?;
    }
    let shortest = match width {
        1 => 0x80,
        2 => 0x100,
        3 => 0x1_0000,
        _ => return None,
    };
    if value < shortest || value > MAX_CONTENT {
        return None;
    }
    Some((value, 1 + width))
}

pub(crate) fn b64_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut clean = Vec::with_capacity(input.len());
    for &byte in input {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => clean.push(byte),
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => return None,
        }
    }
    if clean.is_empty() {
        return None;
    }
    match clean.len() % 4 {
        0 => {}
        2 => clean.extend_from_slice(b"=="),
        3 => clean.push(b'='),
        _ => return None,
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let mut index = 0;
    while index < clean.len() {
        let chunk = &clean[index..index + 4];
        let pads = chunk.iter().filter(|byte| **byte == b'=').count();
        if pads > 2 || (pads > 0 && index + 4 != clean.len()) {
            return None;
        }
        let mut values = [0u8; 4];
        for (slot, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                if slot < 4 - pads {
                    return None;
                }
                continue;
            }
            values[slot] = b64_value(byte)?;
        }
        let packed = (u32::from(values[0]) << 18)
            | (u32::from(values[1]) << 12)
            | (u32::from(values[2]) << 6)
            | u32::from(values[3]);
        out.push((packed >> 16) as u8);
        if pads < 2 {
            out.push((packed >> 8) as u8);
        }
        if pads < 1 {
            out.push(packed as u8);
        }
        index += 4;
    }
    Some(out)
}

fn b64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut block = [0u8; 64];
    let mut filled = 0;
    for &byte in data {
        block[filled] = byte;
        filled += 1;
        if filled == 64 {
            compress(&mut state, &block);
            filled = 0;
        }
    }
    block[filled] = 0x80;
    filled += 1;
    if filled > 56 {
        for byte in &mut block[filled..] {
            *byte = 0;
        }
        compress(&mut state, &block);
        filled = 0;
    }
    for byte in &mut block[filled..56] {
        *byte = 0;
    }
    let bits = u64::try_from(data.len()).unwrap_or(0).saturating_mul(8);
    block[56..].copy_from_slice(&bits.to_be_bytes());
    compress(&mut state, &block);
    let mut out = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut words = [0u32; 64];
    for index in 0..16 {
        let offset = index * 4;
        words[index] = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[index])
            .wrapping_add(words[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMSIGN: &[u8] = include_bytes!("../tests/fixtures/emsign-ecc-g3.der");
    const EMSIGN_SPKI: &[u8] = include_bytes!("../tests/fixtures/emsign-ecc-g3.spki.der");
    const RSA_DER: &[u8] = include_bytes!("../tests/fixtures/probe-rsa.der");
    const RSA_SPKI: &[u8] = include_bytes!("../tests/fixtures/probe-rsa.spki.der");
    const P256_DER: &[u8] = include_bytes!("../tests/fixtures/probe-p256.der");
    const P256_SPKI: &[u8] = include_bytes!("../tests/fixtures/probe-p256.spki.der");
    const ED_DER: &[u8] = include_bytes!("../tests/fixtures/probe-ed25519.der");
    const ED_SPKI: &[u8] = include_bytes!("../tests/fixtures/probe-ed25519.spki.der");
    const NESTED: &[u8] = include_bytes!("../tests/fixtures/probe-nested.der");
    const PEM: &[u8] = include_bytes!("../tests/fixtures/probe-bundle.pem");
    const GZIP: &[u8] = include_bytes!("../tests/fixtures/probe-rsa.der.gz");

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    fn len_bytes(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xff {
            vec![0x81, len as u8]
        } else if len <= 0xffff {
            let be = (len as u16).to_be_bytes();
            vec![0x82, be[0], be[1]]
        } else {
            let be = (len as u32).to_be_bytes();
            vec![0x83, be[1], be[2], be[3]]
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(content.len() + 4);
        out.push(tag);
        out.extend(len_bytes(content.len()));
        out.extend_from_slice(content);
        out
    }

    fn seq(content: &[u8]) -> Vec<u8> {
        tlv(0x30, content)
    }

    fn ed_alg() -> Vec<u8> {
        seq(&tlv(0x06, ED25519))
    }

    fn name(cn: &[u8]) -> Vec<u8> {
        let atv = seq(&cat(&[&tlv(0x06, CN_OID), &tlv(0x13, cn)]));
        seq(&tlv(0x31, &atv))
    }

    fn validity(stamp: &[u8], tag: u8) -> Vec<u8> {
        let time = tlv(tag, stamp);
        seq(&cat(&[&time, &time]))
    }

    fn signature() -> Vec<u8> {
        let mut payload = vec![0x00];
        payload.extend(std::iter::repeat(0x11).take(64));
        tlv(0x03, &payload)
    }

    fn cert_with(stamp: &[u8], tag: u8, cn: &[u8], extra: &[u8]) -> Vec<u8> {
        let alg = ed_alg();
        let mut body = Vec::new();
        body.extend(tlv(0xa0, &tlv(0x02, &[0x02])));
        body.extend(tlv(0x02, &[0x01]));
        body.extend(alg.clone());
        body.extend(name(cn));
        body.extend(validity(stamp, tag));
        body.extend(name(cn));
        body.extend_from_slice(ED_SPKI);
        body.extend_from_slice(extra);
        seq(&cat(&[&seq(&body), &alg, &signature()]))
    }

    fn put_u16(buf: &mut [u8], at: usize, value: u16) {
        buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], at: usize, value: u64) {
        buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn deflate_stored(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = data;
        if rest.is_empty() {
            out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
            return out;
        }
        while !rest.is_empty() {
            let take = rest.len().min(65535);
            let last = take == rest.len();
            out.push(if last { 1 } else { 0 });
            let len = take as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        out
    }

    fn zlib_of(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x78, 0x01];
        out.extend(deflate_stored(data));
        out.extend_from_slice(&inflate::adler32(data).to_be_bytes());
        out
    }

    fn pem_text(data: &[u8]) -> Vec<u8> {
        let mut text = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        text.extend(b64_encode(data));
        text.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
        text
    }

    fn zip_one(name: &str, plain: &[u8], method: u16, payload: &[u8]) -> Vec<u8> {
        let crc = inflate::crc32(plain);
        let name = name.as_bytes();
        let mut local = Vec::new();
        local.extend_from_slice(b"PK\x03\x04");
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        local.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(payload);
        let mut central = Vec::new();
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        central.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(name);
        let cd_off = local.len() as u32;
        let mut out = local;
        out.extend_from_slice(&central);
        let cd_size = (out.len() as u32) - cd_off;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn elf_with(section: &[u8], overlay: &[u8]) -> Vec<u8> {
        elf_named(b".rodata", section)
            .into_iter()
            .chain(overlay.iter().copied())
            .collect()
    }

    fn elf_named(section_name: &[u8], section: &[u8]) -> Vec<u8> {
        let mut strtab = vec![0];
        let name_at = strtab.len();
        strtab.extend_from_slice(section_name);
        strtab.push(0);
        let str_name = strtab.len();
        strtab.extend_from_slice(b".shstrtab");
        strtab.push(0);
        let ph_off = 64usize;
        let ro_off = 120usize;
        let str_off = ro_off + section.len();
        let sh_off = str_off + strtab.len();
        let mut blob = vec![0u8; sh_off + 64 * 3];
        blob[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        blob[4] = 2;
        blob[5] = 1;
        blob[6] = 1;
        put_u16(&mut blob, 16, 2);
        put_u16(&mut blob, 18, 0x3e);
        put_u32(&mut blob, 20, 1);
        put_u64(&mut blob, 32, ph_off as u64);
        put_u64(&mut blob, 40, sh_off as u64);
        put_u16(&mut blob, 52, 64);
        put_u16(&mut blob, 54, 56);
        put_u16(&mut blob, 56, 1);
        put_u16(&mut blob, 58, 64);
        put_u16(&mut blob, 60, 3);
        put_u16(&mut blob, 62, 2);
        put_u32(&mut blob, ph_off, 1);
        put_u64(&mut blob, ph_off + 8, ro_off as u64);
        put_u64(&mut blob, ph_off + 32, section.len() as u64);
        blob[ro_off..ro_off + section.len()].copy_from_slice(section);
        blob[str_off..str_off + strtab.len()].copy_from_slice(&strtab);
        let s1 = sh_off + 64;
        put_u32(&mut blob, s1, name_at as u32);
        put_u32(&mut blob, s1 + 4, 1);
        put_u64(&mut blob, s1 + 24, ro_off as u64);
        put_u64(&mut blob, s1 + 32, section.len() as u64);
        let s2 = sh_off + 128;
        put_u32(&mut blob, s2, str_name as u32);
        put_u32(&mut blob, s2 + 4, 3);
        put_u64(&mut blob, s2 + 24, str_off as u64);
        put_u64(&mut blob, s2 + 32, strtab.len() as u64);
        blob
    }

    fn pe_with_signer(cert: &[u8]) -> Vec<u8> {
        let opt_size = 240u16;
        let lfanew = 0x40u32;
        let opt = (lfanew as usize) + 24;
        let section = opt + opt_size as usize;
        let body = section + 40;
        let mut blob = vec![0u8; body + cert.len()];
        blob[0] = b'M';
        blob[1] = b'Z';
        put_u32(&mut blob, 0x3c, lfanew);
        blob[lfanew as usize..lfanew as usize + 4].copy_from_slice(b"PE\0\0");
        let coff = lfanew as usize + 4;
        put_u16(&mut blob, coff, 0x8664);
        put_u16(&mut blob, coff + 2, 1);
        put_u16(&mut blob, coff + 16, opt_size);
        put_u16(&mut blob, coff + 18, 2);
        put_u16(&mut blob, opt, 0x20b);
        put_u32(&mut blob, opt + 16, 0x1000);
        put_u32(&mut blob, opt + 60, body as u32);
        put_u32(&mut blob, opt + 108, 16);
        put_u32(&mut blob, opt + 144, body as u32);
        put_u32(&mut blob, opt + 148, cert.len() as u32);
        blob[section..section + 6].copy_from_slice(b".rdata");
        put_u32(&mut blob, section + 8, cert.len() as u32);
        put_u32(&mut blob, section + 12, 0x1000);
        put_u32(&mut blob, section + 16, cert.len() as u32);
        put_u32(&mut blob, section + 20, body as u32);
        blob[body..body + cert.len()].copy_from_slice(cert);
        blob
    }

    fn macho_with_signer(cert: &[u8]) -> Vec<u8> {
        let cert_off = 32 + 72 + 16;
        let mut blob = vec![0u8; cert_off + cert.len()];
        blob[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        put_u32(&mut blob, 4, 0x0100_0007);
        put_u32(&mut blob, 12, 2);
        put_u32(&mut blob, 16, 2);
        put_u32(&mut blob, 20, 88);
        put_u32(&mut blob, 32, 0x19);
        put_u32(&mut blob, 36, 72);
        blob[40..50].copy_from_slice(b"__LINKEDIT");
        put_u64(&mut blob, 72, cert_off as u64);
        put_u64(&mut blob, 80, cert.len() as u64);
        put_u32(&mut blob, 104, 0x1d);
        put_u32(&mut blob, 108, 16);
        put_u32(&mut blob, 112, cert_off as u32);
        put_u32(&mut blob, 116, cert.len() as u32);
        blob[cert_off..].copy_from_slice(cert);
        blob
    }

    fn b64_encode(data: &[u8]) -> Vec<u8> {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut index = 0;
        while index + 3 <= data.len() {
            let packed = (u32::from(data[index]) << 16)
                | (u32::from(data[index + 1]) << 8)
                | u32::from(data[index + 2]);
            out.push(ALPHA[((packed >> 18) & 63) as usize]);
            out.push(ALPHA[((packed >> 12) & 63) as usize]);
            out.push(ALPHA[((packed >> 6) & 63) as usize]);
            out.push(ALPHA[(packed & 63) as usize]);
            index += 3;
        }
        if index < data.len() {
            let mut packed = u32::from(data[index]) << 16;
            if index + 1 < data.len() {
                packed |= u32::from(data[index + 1]) << 8;
            }
            out.push(ALPHA[((packed >> 18) & 63) as usize]);
            out.push(ALPHA[((packed >> 12) & 63) as usize]);
            if index + 1 < data.len() {
                out.push(ALPHA[((packed >> 6) & 63) as usize]);
                out.push(b'=');
            } else {
                out.extend_from_slice(b"==");
            }
        }
        out
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn an_emsign_certificate_is_full() {
        let hits = scan(EMSIGN);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].length, 594);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].encoding, Encoding::Der);
        assert_eq!(
            hex(&hits[0].sha256),
            "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
        );
        assert_eq!(
            hex(&hits[0].spki_sha256),
            "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782"
        );
        assert_eq!(
            hits[0].subject_cn.as_deref(),
            Some("emSign ECC Root CA - G3")
        );
    }

    #[test]
    fn an_unwrapped_spki_is_an_anchor() {
        for spki in [EMSIGN_SPKI, ED_SPKI, P256_SPKI, RSA_SPKI] {
            assert_eq!(spki[0], 0x30);
            let header = if spki[1] < 0x80 {
                2
            } else if spki[1] == 0x81 {
                3
            } else {
                4
            };
            let content = &spki[header..];
            let hits = scan(content);
            assert_eq!(hits.len(), 1, "{}", content.len());
            assert_eq!(hits[0].kind, Kind::Anchor);
            assert_eq!(hits[0].length, content.len());
            assert_eq!(hits[0].sha256, sha256(spki));
            assert_eq!(hits[0].spki_sha256, sha256(spki));
            assert_eq!(hits[0].subject_cn, None);
            assert_eq!(scan(spki).len(), 1);
        }
    }

    #[test]
    fn an_emsign_spki_is_an_anchor() {
        let hits = scan(EMSIGN_SPKI);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Anchor);
        assert_eq!(hits[0].encoding, Encoding::Der);
        assert_eq!(hits[0].length, 120);
        assert_eq!(EMSIGN_SPKI[0], 0x30);
        assert!(EMSIGN_SPKI[1] < 0x80);
        assert_eq!(hits[0].sha256, sha256(EMSIGN_SPKI));
        assert_eq!(hits[0].spki_sha256, hits[0].sha256);
        assert_eq!(hits[0].subject_cn, None);
        assert_eq!(
            hex(&hits[0].sha256),
            "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782"
        );
    }

    #[test]
    fn openssl_probe_certificates_are_full() {
        for (der, spki, cn, digest) in [
            (
                RSA_DER,
                RSA_SPKI,
                "probe-rsa",
                "c3cf2905cc5c61ca49da61ecdc4135124016787013488db4465bec9245443c46",
            ),
            (
                P256_DER,
                P256_SPKI,
                "probe-p256",
                "b178a1d81eb98d8d6c1bea7766a831f335ac02ef81623f6368a7fbafcb059e7b",
            ),
            (
                ED_DER,
                ED_SPKI,
                "probe-ed25519",
                "37987cdcf09fbad463ad9e148cbc28f7ee4d6214c8b2e4c85001ee4ba9b986cb",
            ),
        ] {
            let hits = scan(der);
            assert_eq!(hits.len(), 1, "{cn}");
            assert_eq!(hits[0].kind, Kind::Full);
            assert_eq!(hits[0].encoding, Encoding::Der);
            assert_eq!(hits[0].subject_cn.as_deref(), Some(cn));
            assert_eq!(hex(&hits[0].sha256), digest);
            assert_eq!(hits[0].spki_sha256, sha256(spki));
            let keys = scan(spki);
            assert_eq!(keys.len(), 1, "{cn} spki");
            assert_eq!(keys[0].kind, Kind::Anchor);
            assert_eq!(keys[0].subject_cn, None);
            assert_eq!(keys[0].sha256, keys[0].spki_sha256);
            assert_eq!(keys[0].length, spki.len());
        }
        assert_eq!(ED_SPKI[1], 0x2a);
        assert_eq!(P256_SPKI[1], 0x59);
        assert_eq!(RSA_SPKI[1], 0x82);
    }

    #[test]
    fn a_nested_certificate_is_its_own_hit() {
        let hits = scan(NESTED);
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|hit| hit.kind == Kind::Full));
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].subject_cn.as_deref(), Some("probe-outer"));
        assert_eq!(hits[0].sha256, sha256(NESTED));
        assert_eq!(hits[1].offset, 527);
        assert_eq!(hits[1].length, P256_DER.len());
        assert_eq!(hits[1].sha256, sha256(P256_DER));
        assert_eq!(hits[1].subject_cn.as_deref(), Some("probe-p256"));
        assert_eq!(hits[1].encoding, Encoding::Der);
    }

    #[test]
    fn a_pem_bundle_is_three_hits() {
        let hits = scan(PEM);
        assert_eq!(hits.len(), 3);
        assert!(hits
            .iter()
            .all(|hit| hit.kind == Kind::Full && hit.encoding == Encoding::Pem));
        let mut got: Vec<_> = hits.iter().map(|hit| hit.sha256).collect();
        got.sort();
        let mut expect = vec![sha256(RSA_DER), sha256(P256_DER), sha256(ED_DER)];
        expect.sort();
        assert_eq!(got, expect);
        let mut names: Vec<_> = hits
            .iter()
            .map(|hit| hit.subject_cn.clone().unwrap_or_default())
            .collect();
        names.sort();
        assert_eq!(names, ["probe-ed25519", "probe-p256", "probe-rsa"]);
        let mut mixed = PEM.to_vec();
        mixed.extend_from_slice(EMSIGN);
        let mixed_hits = scan(&mixed);
        assert_eq!(mixed_hits.len(), 4);
        assert_eq!(mixed_hits[3].encoding, Encoding::Der);
        assert_eq!(mixed_hits[3].sha256, sha256(EMSIGN));
    }

    #[test]
    fn bare_base64_is_one_hit() {
        let text = b64_encode(EMSIGN);
        let hits = scan(&text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Encoding::Base64);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].length, text.len());
        assert_eq!(hits[0].sha256, sha256(EMSIGN));
        assert_eq!(
            hits[0].subject_cn.as_deref(),
            Some("emSign ECC Root CA - G3")
        );
        let mut wrapped = vec![0x2a];
        wrapped.extend_from_slice(&text);
        wrapped.push(b'*');
        let wrapped_hits = scan(&wrapped);
        assert_eq!(wrapped_hits.len(), 1);
        assert_eq!(wrapped_hits[0].encoding, Encoding::Base64);
        let mut loose = vec![0u8; 8];
        loose.extend_from_slice(EMSIGN);
        assert!(scan(&b64_encode(&loose)).is_empty());
    }

    #[test]
    fn a_gzip_member_is_one_full_hit() {
        let hits = scan(GZIP);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].container, Container::Gzip);
        assert_eq!(hits[0].encoding, Encoding::Der);
        assert_eq!(hits[0].role, Role::Trust);
        assert_eq!(hits[0].place, "file");
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].length, GZIP.len());
        assert_eq!(hits[0].sha256, sha256(RSA_DER));
        assert_eq!(hits[0].subject_cn.as_deref(), Some("probe-rsa"));
    }

    #[test]
    fn a_zlib_stream_is_one_full_hit() {
        let wrapped = zlib_of(ED_DER);
        let hits = scan(&wrapped);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].container, Container::Zlib);
        assert_eq!(hits[0].sha256, sha256(ED_DER));
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].length, wrapped.len());
        assert_eq!(hits[0].place, "file");
    }

    #[test]
    fn a_deflated_zip_entry_is_one_full_hit() {
        let payload = deflate_stored(ED_DER);
        let mut zip = zip_one("ed.der", ED_DER, 8, &payload);
        zip.extend_from_slice(b"PYINST");
        let hits = scan(&zip);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].container, Container::Zip);
        assert_eq!(hits[0].sha256, sha256(ED_DER));
        assert_eq!(hits[0].place, "file");
        assert_eq!(hits[0].subject_cn.as_deref(), Some("probe-ed25519"));
    }

    #[test]
    fn an_elf_section_overlay_and_zip_keep_their_places() {
        let mut bytes = elf_with(ED_SPKI, &[]);
        let zip = zip_one("p256.der", P256_DER, 0, P256_DER);
        bytes.extend_from_slice(&zip);
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].kind, Kind::Anchor);
        assert_eq!(hits[0].place, ".rodata");
        assert_eq!(hits[0].container, Container::File);
        assert_eq!(hits[0].sha256, sha256(ED_SPKI));
        assert_eq!(hits[1].kind, Kind::Full);
        assert_eq!(hits[1].place, "overlay");
        assert_eq!(hits[1].container, Container::Zip);
        assert_eq!(hits[1].sha256, sha256(P256_DER));
        let over = elf_with(ED_SPKI, ED_DER);
        let over_hits = scan(&over);
        assert!(over_hits.iter().any(|hit| {
            hit.kind == Kind::Full && hit.place == "overlay" && hit.sha256 == sha256(ED_DER)
        }));
    }

    #[test]
    fn a_sea_section_marks_the_container() {
        let bytes = elf_named(b"NODE_SEA_BLOB", ED_SPKI);
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].container, Container::Sea);
        assert_eq!(hits[0].place, "NODE_SEA_BLOB");
        assert_eq!(hits[0].kind, Kind::Anchor);
        assert_eq!(hits[0].role, Role::Trust);
    }

    #[test]
    fn a_pe_certificate_table_is_a_signer() {
        let bytes = pe_with_signer(ED_DER);
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].role, Role::Signer);
        assert_eq!(hits[0].place, ".rdata");
        assert_eq!(hits[0].sha256, sha256(ED_DER));
    }

    #[test]
    fn a_macho_code_signature_is_a_signer() {
        let bytes = macho_with_signer(ED_DER);
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].role, Role::Signer);
        assert_eq!(hits[0].place, "__LINKEDIT");
        assert_eq!(hits[0].sha256, sha256(ED_DER));
    }

    #[test]
    fn utf16_pem_is_one_full_hit() {
        let text = pem_text(ED_DER);
        let mut wide = Vec::new();
        for byte in &text {
            wide.push(*byte);
            wide.push(0);
        }
        let hits = scan(&wide);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].encoding, Encoding::Pem);
        assert_eq!(hits[0].sha256, sha256(ED_DER));
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].length, wide.len() - 2);
        assert_eq!(hits[0].place, "file");
    }

    #[test]
    fn pins_match_a_cert_hash_and_skip_noise() {
        let digest = sha256(EMSIGN);
        let spki = sha256(EMSIGN_SPKI);
        let mut bytes = EMSIGN.to_vec();
        bytes.extend_from_slice(b"sha256/");
        let text_at = bytes.len() - b"sha256/".len();
        let text = b64_encode(&digest);
        bytes.extend_from_slice(&text);
        let text_len = b"sha256/".len() + text.len();
        bytes.extend_from_slice(b" sha1/aaaaaaaa sha256/not-a-pin ");
        let raw_at = bytes.len();
        bytes.extend_from_slice(&spki);
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(b"sha256/");
        bytes.extend_from_slice(&b64_encode(&[0xab; 32]));
        let hits = scan(&bytes);
        let pins: Vec<_> = hits.iter().filter(|hit| hit.kind == Kind::Pin).collect();
        assert_eq!(pins.len(), 3);
        assert_eq!(pins[0].encoding, Encoding::Base64);
        assert_eq!(pins[0].offset, text_at);
        assert_eq!(pins[0].length, text_len);
        assert_eq!(pins[0].sha256, digest);
        assert_eq!(
            pins[0].subject_cn.as_deref(),
            Some("emSign ECC Root CA - G3")
        );
        assert_eq!(pins[1].encoding, Encoding::Der);
        assert_eq!(pins[1].offset, raw_at);
        assert_eq!(pins[1].length, 32);
        assert_eq!(pins[1].sha256, spki);
        assert_eq!(
            pins[1].subject_cn.as_deref(),
            Some("emSign ECC Root CA - G3")
        );
        assert_eq!(pins[2].encoding, Encoding::Base64);
        assert_eq!(pins[2].sha256, [0xab; 32]);
        assert_eq!(pins[2].subject_cn, None);
        assert_eq!(hits.iter().filter(|hit| hit.kind == Kind::Full).count(), 1);
    }

    #[test]
    fn offset_and_generalized_times_are_hits() {
        let offset = cert_with(b"250101000000+0000", 0x17, b"offset", &[]);
        let hits = scan(&offset);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].subject_cn.as_deref(), Some("offset"));
        let generalized = cert_with(b"20250101000000Z", 0x18, b"general", &[]);
        assert_eq!(scan(&generalized).len(), 1);
        let minus = cert_with(b"20250101000000-0500", 0x18, b"minus", &[]);
        assert_eq!(scan(&minus).len(), 1);
        let bad = cert_with(b"250101000000+00", 0x17, b"bad", &[]);
        assert!(scan(&bad).iter().all(|hit| hit.kind != Kind::Full));
    }

    #[test]
    fn trust_anchor_info_keeps_a_key_id() {
        let tai = seq(&cat(&[
            &tlv(0x02, &[0x01]),
            ED_SPKI,
            &tlv(0x04, &[1, 2, 3, 4]),
        ]));
        let hits = scan(&tai);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Anchor);
        assert_eq!(hits[0].subject_cn, None);
        assert_eq!(hits[0].spki_sha256, sha256(ED_SPKI));
        assert_ne!(hits[0].sha256, hits[0].spki_sha256);
        assert_eq!(hits[0].length, tai.len());
        let empty_id = seq(&cat(&[&tlv(0x02, &[0x01]), ED_SPKI, &tlv(0x04, &[])]));
        assert!(scan(&empty_id).iter().all(|hit| hit.offset != 0));
        let long_id = seq(&cat(&[
            &tlv(0x02, &[0x01]),
            ED_SPKI,
            &tlv(0x04, &[0u8; 65]),
        ]));
        assert!(scan(&long_id).iter().all(|hit| hit.offset != 0));
    }

    #[test]
    fn a_bare_body_is_not_an_anchor() {
        let alg = ed_alg();
        let mut body = Vec::new();
        body.extend(tlv(0xa0, &tlv(0x02, &[0x02])));
        body.extend(tlv(0x02, &[0x01]));
        body.extend(alg);
        body.extend(name(b"body"));
        body.extend(validity(b"250101000000Z", 0x17));
        body.extend(name(b"body"));
        body.extend_from_slice(ED_SPKI);
        let tbs = seq(&body);
        let hits = scan(&tbs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Body);
        assert_eq!(hits[0].subject_cn.as_deref(), Some("body"));
        assert_eq!(hits[0].spki_sha256, sha256(ED_SPKI));
        assert_eq!(hits[0].sha256, sha256(&tbs));
    }

    #[test]
    fn an_unknown_key_is_not_a_hit() {
        let oid = tlv(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        );
        let alg = seq(&cat(&[&oid, &tlv(0x05, &[])]));
        let mut payload = vec![0x00];
        payload.extend(std::iter::repeat(0x11).take(32));
        let bits = tlv(0x03, &payload);
        assert!(scan(&seq(&cat(&[&alg, &bits]))).is_empty());
        let rsa_oid = tlv(0x06, RSA);
        let rsa_alg = seq(&cat(&[&rsa_oid, &tlv(0x05, &[])]));
        let mut short = vec![0x40];
        short.extend(std::iter::repeat(0x11).take(31));
        let mut payload = vec![0x00];
        payload.extend(seq(&cat(&[
            &tlv(0x02, &short),
            &tlv(0x02, &[0x01, 0x00, 0x01]),
        ])));
        let short_bits = tlv(0x03, &payload);
        assert!(scan(&seq(&cat(&[&rsa_alg, &short_bits]))).is_empty());
    }

    #[test]
    fn a_mismatched_signature_algorithm_is_not_a_hit() {
        let alg = ed_alg();
        let other = seq(&cat(&[
            &tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
            ),
            &tlv(0x05, &[]),
        ]));
        let mut body = Vec::new();
        body.extend(tlv(0xa0, &tlv(0x02, &[0x02])));
        body.extend(tlv(0x02, &[0x01]));
        body.extend(alg);
        body.extend(name(b"mix"));
        body.extend(validity(b"250101000000Z", 0x17));
        body.extend(name(b"mix"));
        body.extend_from_slice(ED_SPKI);
        let bytes = seq(&cat(&[&seq(&body), &other, &signature()]));
        let hits = scan(&bytes);
        assert!(hits.iter().all(|hit| hit.kind != Kind::Full));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Body);
        assert_eq!(hits[0].subject_cn.as_deref(), Some("mix"));
    }

    #[test]
    fn ber_indefinite_length_is_not_a_hit() {
        assert!(scan(&[0x30, 0x80, 0x00, 0x00]).is_empty());
        let mut wrapped = vec![0x30, 0x80];
        wrapped.extend_from_slice(ED_SPKI);
        wrapped.extend_from_slice(&[0x00, 0x00]);
        let hits = scan(&wrapped);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 2);
        assert_eq!(hits[0].kind, Kind::Anchor);
        assert_ne!(hits[0].offset, 0);
    }

    #[test]
    fn a_noncanonical_length_is_not_a_hit() {
        assert_eq!(ED_SPKI[0], 0x30);
        assert!(ED_SPKI[1] < 0x80);
        let mut long = vec![0x30, 0x81, ED_SPKI[1]];
        long.extend_from_slice(&ED_SPKI[2..]);
        let hits = scan(&long);
        assert_eq!(hits.len(), 1);
        assert_ne!(hits[0].offset, 0);
        assert_eq!(hits[0].sha256, sha256(ED_SPKI));
        let mut wide = vec![0x30, 0x83, 0x00, 0x00, ED_SPKI[1]];
        wide.extend_from_slice(&ED_SPKI[2..]);
        let hits = scan(&wide);
        assert_eq!(hits.len(), 1);
        assert_ne!(hits[0].offset, 0);
        assert_eq!(hits[0].sha256, sha256(ED_SPKI));
    }

    #[test]
    fn a_three_byte_length_certificate_is_full() {
        let extra = tlv(0xa3, &vec![0u8; 0x1_0000]);
        let bytes = cert_with(b"250101000000Z", 0x17, b"wide", &extra);
        assert_eq!(bytes[0], 0x30);
        assert_eq!(bytes[1], 0x83);
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].length, bytes.len());
        assert_eq!(hits[0].subject_cn.as_deref(), Some("wide"));
        assert!(bytes.len() > 0x1_0000);
    }

    #[test]
    fn a_rejected_sequence_does_not_hide_a_later_certificate() {
        let mut bytes = vec![0x30, 0x82, 0xff, 0xff];
        bytes.extend_from_slice(EMSIGN);
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 4);
        assert_eq!(hits[0].sha256, sha256(EMSIGN));
        assert!(scan(&[0x30, 0x04, 0x01, 0x01, 0x00, 0x00]).is_empty());
    }

    #[test]
    fn the_library_function_matches_scan() {
        assert_eq!(crate::certs(EMSIGN), scan(EMSIGN));
        assert_eq!(crate::certs(PEM), scan(PEM));
    }
}
