/*
---
why: This file finds embedded certificates and trust anchors in a binary.
uses: bininfo
how: bininfo calls this file to scan read-only bytes.
This file does not print the page.
---
*/

//! Scan a byte slice for ASN.1 certificate sequences.
//! A full certificate has an X.509 body, a signature algorithm, and a signature.
//! A trust anchor is a smaller DER fragment.

/// One hit in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// File offset of the first byte.
    pub offset: usize,
    /// Length of the SEQUENCE. The count includes the tag and the length bytes.
    pub length: usize,
    /// Full certificate or minimal trust-anchor fragment.
    pub kind: Kind,
}

/// Full X.509 certificate or a smaller trust-anchor fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The bytes have the X.509 certificate shape.
    Full,
    /// The bytes are a public key, trust-anchor info, or a certificate body.
    Anchor,
}

/// Scan `bytes` for embedded certificates and trust anchors.
///
/// A hit starts at the long-form SEQUENCE tag `30 81` or `30 82`.
/// The length uses the shortest DER form.
/// The scan moves to the first byte after an accepted hit.
/// The scan reads the bytes inside a rejected sequence.
pub fn scan(bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !long_sequence_at(bytes, index) {
            index += 1;
            continue;
        }
        let Some(total) = sequence_len(&bytes[index..]) else {
            index += 1;
            continue;
        };
        let Some(end) = index.checked_add(total) else {
            index += 1;
            continue;
        };
        if end > bytes.len() || end <= index {
            index += 1;
            continue;
        }
        if let Some(kind) = classify(&bytes[index..end]) {
            hits.push(Hit {
                offset: index,
                length: total,
                kind,
            });
            index = end;
        } else {
            index += 1;
        }
    }
    hits
}

struct Part<'a> {
    tag: u8,
    content: &'a [u8],
}

fn long_sequence_at(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&0x30) && matches!(bytes.get(index + 1), Some(0x81 | 0x82))
}

fn sequence_len(bytes: &[u8]) -> Option<usize> {
    if !matches!(bytes.get(1), Some(0x81 | 0x82)) {
        return None;
    }
    let (tag, _content, end) = next_part(bytes, 0)?;
    if tag != 0x30 {
        return None;
    }
    Some(end)
}

fn classify(slice: &[u8]) -> Option<Kind> {
    let (tag, content, end) = next_part(slice, 0)?;
    if tag != 0x30 || end != slice.len() || !matches!(slice.get(1), Some(0x81 | 0x82)) {
        return None;
    }
    let kids = parts(content)?;
    if is_cert(&kids) {
        Some(Kind::Full)
    } else if is_anchor(&kids) {
        Some(Kind::Anchor)
    } else {
        None
    }
}

fn is_cert(kids: &[Part<'_>]) -> bool {
    if kids.len() != 3 || kids[0].tag != 0x30 || kids[1].tag != 0x30 || kids[2].tag != 0x03 {
        return false;
    }
    if !alg_ok(kids[1].content) || !bit_ok(kids[2].content) {
        return false;
    }
    let Some(body) = parts(kids[0].content) else {
        return false;
    };
    tbs_parts_ok(&body, Some(kids[1].content))
}

fn is_anchor(kids: &[Part<'_>]) -> bool {
    is_spki_kids(kids) || is_tai(kids) || tbs_parts_ok(kids, None)
}

fn is_spki_kids(kids: &[Part<'_>]) -> bool {
    kids.len() == 2
        && kids[0].tag == 0x30
        && alg_ok(kids[0].content)
        && kids[1].tag == 0x03
        && bit_ok(kids[1].content)
}

fn is_spki_content(content: &[u8]) -> bool {
    match parts(content) {
        Some(fields) => is_spki_kids(&fields),
        None => false,
    }
}

fn is_tai(kids: &[Part<'_>]) -> bool {
    match kids {
        [key] if key.tag == 0x30 => is_spki_content(key.content),
        [version, key] if version.tag == 0x02 && key.tag == 0x30 => {
            version_one(version.content) && is_spki_content(key.content)
        }
        _ => false,
    }
}

fn tbs_parts_ok(fields: &[Part<'_>], signature_alg: Option<&[u8]>) -> bool {
    let mut rest = fields;
    if let Some(first) = rest.first() {
        if first.tag == 0xa0 {
            if !version_ok(first.content) {
                return false;
            }
            rest = &rest[1..];
        }
    }
    if rest.len() < 6 {
        return false;
    }
    if rest[0].tag != 0x02 || !serial_ok(rest[0].content) {
        return false;
    }
    if rest[1].tag != 0x30 || !alg_ok(rest[1].content) {
        return false;
    }
    if let Some(signature_alg) = signature_alg {
        if rest[1].content != signature_alg {
            return false;
        }
    }
    if rest[2].tag != 0x30 || !name_ok(rest[2].content) {
        return false;
    }
    if rest[3].tag != 0x30 || !validity_ok(rest[3].content) {
        return false;
    }
    if rest[4].tag != 0x30 || !name_ok(rest[4].content) {
        return false;
    }
    if rest[5].tag != 0x30 || !is_spki_content(rest[5].content) {
        return false;
    }
    rest[6..].iter().all(|field| field.tag & 0xc0 == 0x80)
}

fn version_ok(content: &[u8]) -> bool {
    let Some(fields) = parts(content) else {
        return false;
    };
    if fields.len() != 1 || fields[0].tag != 0x02 {
        return false;
    }
    integer_ok(fields[0].content) && matches!(unsigned(fields[0].content), Some(0..=2))
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
    let Some(fields) = parts(content) else {
        return false;
    };
    if fields.is_empty() || fields.len() > 2 || fields[0].tag != 0x06 {
        return false;
    }
    oid_ok(fields[0].content)
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
    match parts(content) {
        Some(fields) => fields.iter().all(|field| field.tag == 0x31),
        None => false,
    }
}

fn validity_ok(content: &[u8]) -> bool {
    let Some(fields) = parts(content) else {
        return false;
    };
    fields.len() == 2 && fields.iter().all(|field| time_ok(field.tag, field.content))
}

fn time_ok(tag: u8, content: &[u8]) -> bool {
    let digits = match tag {
        0x17 => 12,
        0x18 => 14,
        _ => return false,
    };
    if content.len() != digits + 1 || content[digits] != b'Z' {
        return false;
    }
    content[..digits].iter().all(u8::is_ascii_digit)
}

fn bit_ok(content: &[u8]) -> bool {
    let Some((unused, payload)) = content.split_first() else {
        return false;
    };
    *unused == 0 && payload.len() >= 8
}

fn parts(bytes: &[u8]) -> Option<Vec<Part<'_>>> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let (tag, content, end) = next_part(bytes, index)?;
        if end <= index {
            return None;
        }
        out.push(Part { tag, content });
        index = end;
    }
    Some(out)
}

fn next_part(bytes: &[u8], index: usize) -> Option<(u8, &[u8], usize)> {
    if index >= bytes.len() {
        return None;
    }
    let tag = bytes[index];
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (content_len, len_bytes) = der_len(&bytes[index + 1..])?;
    let header = len_bytes.checked_add(1)?;
    let total = header.checked_add(content_len)?;
    let end = index.checked_add(total)?;
    if end > bytes.len() {
        return None;
    }
    Some((tag, &bytes[index + header..end], end))
}

fn der_len(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let width = usize::from(first & 0x7f);
    if width == 0 || width > 2 || bytes.len() < 1 + width {
        return None;
    }
    let mut value = 0usize;
    for byte in &bytes[1..1 + width] {
        value = (value << 8) | usize::from(*byte);
    }
    let shortest = if width == 1 { 0x80 } else { 0x100 };
    if value < shortest {
        return None;
    }
    Some((value, 1 + width))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    const OTHER_OID: &[u8] = &[0x2b, 0x01];

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
        } else {
            let wide = u16::try_from(len).expect("length fits in two bytes");
            let be = wide.to_be_bytes();
            vec![0x82, be[0], be[1]]
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

    fn alg(oid_bytes: &[u8]) -> Vec<u8> {
        seq(&cat(&[&tlv(0x06, oid_bytes), &tlv(0x05, &[])]))
    }

    fn time(generalized: bool) -> Vec<u8> {
        if generalized {
            tlv(0x18, b"20250101000000Z")
        } else {
            tlv(0x17, b"250101000000Z")
        }
    }

    fn validity(generalized: bool) -> Vec<u8> {
        let stamp = time(generalized);
        seq(&cat(&[&stamp, &stamp]))
    }

    fn name() -> Vec<u8> {
        let oid = tlv(0x06, &[0x55, 0x04, 0x03]);
        let text = tlv(0x13, b"a");
        let set = tlv(0x31, &seq(&cat(&[&oid, &text])));
        seq(&set)
    }

    fn key_bits(len: usize) -> Vec<u8> {
        let mut payload = vec![0x11; len];
        payload.insert(0, 0x00);
        tlv(0x03, &payload)
    }

    fn spki(key_len: usize) -> Vec<u8> {
        seq(&cat(&[&alg(OID), &key_bits(key_len)]))
    }

    fn tbs(key_len: usize, version: bool, generalized: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if version {
            body.extend(tlv(0xa0, &tlv(0x02, &[0x02])));
        }
        body.extend(tlv(0x02, &[0x01]));
        body.extend(alg(OID));
        body.extend(name());
        body.extend(validity(generalized));
        body.extend(name());
        body.extend(spki(key_len));
        seq(&body)
    }

    fn certificate(
        key_len: usize,
        sig_len: usize,
        version: bool,
        generalized: bool,
        oid_bytes: &[u8],
    ) -> Vec<u8> {
        seq(&cat(&[
            &tbs(key_len, version, generalized),
            &alg(oid_bytes),
            &key_bits(sig_len),
        ]))
    }

    fn full_cert() -> Vec<u8> {
        certificate(16, 40, true, false, OID)
    }

    fn wide_cert() -> Vec<u8> {
        certificate(300, 40, true, false, OID)
    }

    fn one(bytes: &[u8]) -> Hit {
        let hits = scan(bytes);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].offset + hits[0].length <= bytes.len());
        hits[0].clone()
    }

    fn assert_form(bytes: &[u8], len_byte: u8) {
        assert_eq!(bytes[0], 0x30);
        assert_eq!(
            bytes[1],
            len_byte,
            "header {:02x?}",
            &bytes[..4.min(bytes.len())]
        );
    }

    #[test]
    fn a_short_form_sequence_is_not_a_hit() {
        let bytes = [0x30, 0x04, 0x01, 0x01, 0x00, 0x00];
        assert!(scan(&bytes).is_empty());
    }

    #[test]
    fn a_two_byte_length_below_256_is_not_a_hit() {
        let mut bytes = vec![0x30, 0x82, 0x00, 0x20];
        bytes.extend_from_slice(&[0x30, 0x82, 0x00, 0x10]);
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&[0u8; 12]);
        assert_eq!(bytes.len(), 36);
        assert!(scan(&bytes).is_empty());
    }

    #[test]
    fn a_one_byte_long_length_below_128_is_not_a_hit() {
        let mut bytes = vec![0x30, 0x81, 0x04];
        bytes.extend_from_slice(&[0u8; 4]);
        assert!(scan(&bytes).is_empty());
    }

    #[test]
    fn a_narrow_certificate_is_full() {
        let bytes = full_cert();
        assert_form(&bytes, 0x81);
        let hit = one(&bytes);
        assert_eq!(hit.kind, Kind::Full);
        assert_eq!(hit.offset, 0);
        assert_eq!(hit.length, bytes.len());
    }

    #[test]
    fn a_wide_certificate_is_full_and_hides_inner_sequences() {
        let bytes = wide_cert();
        assert_form(&bytes, 0x82);
        assert!(bytes[4..].windows(2).any(|pair| pair == [0x30, 0x82]));
        let hit = one(&bytes);
        assert_eq!(hit.kind, Kind::Full);
        assert_eq!(hit.length, bytes.len());
    }

    #[test]
    fn a_generalized_time_certificate_is_full() {
        let bytes = certificate(16, 40, true, true, OID);
        assert_form(&bytes, 0x81);
        assert_eq!(one(&bytes).kind, Kind::Full);
    }

    #[test]
    fn a_versionless_certificate_is_full() {
        let bytes = certificate(16, 40, false, false, OID);
        assert_form(&bytes, 0x81);
        assert_eq!(one(&bytes).kind, Kind::Full);
    }

    #[test]
    fn a_mismatched_signature_algorithm_is_not_a_hit() {
        let bytes = certificate(16, 40, true, false, OTHER_OID);
        assert_form(&bytes, 0x81);
        assert!(scan(&bytes).is_empty());
    }

    #[test]
    fn a_narrow_public_key_is_an_anchor() {
        let bytes = spki(128);
        assert_form(&bytes, 0x81);
        let hit = one(&bytes);
        assert_eq!(hit.kind, Kind::Anchor);
        assert_eq!(hit.length, bytes.len());
    }

    #[test]
    fn a_wide_public_key_is_an_anchor() {
        let bytes = spki(300);
        assert_form(&bytes, 0x82);
        assert_eq!(one(&bytes).kind, Kind::Anchor);
    }

    #[test]
    fn trust_anchor_info_is_an_anchor() {
        let key = spki(128);
        let bytes = seq(&cat(&[&tlv(0x02, &[0x01]), &key]));
        assert!(matches!(bytes[1], 0x81 | 0x82));
        assert_eq!(one(&bytes).kind, Kind::Anchor);
    }

    #[test]
    fn a_certificate_body_is_an_anchor() {
        let bytes = tbs(200, true, false);
        assert!(matches!(bytes[1], 0x81 | 0x82));
        assert_eq!(one(&bytes).kind, Kind::Anchor);
    }

    #[test]
    fn a_loose_outer_sequence_does_not_hide_a_certificate() {
        let cert = wide_cert();
        let span = 1 + cert.len();
        assert!(span >= 0x100 && span <= usize::from(u16::MAX));
        let mut bytes = vec![0x30, 0x82];
        bytes.extend_from_slice(&u16::try_from(span).unwrap().to_be_bytes());
        bytes.push(0xff);
        bytes.extend_from_slice(&cert);
        let hit = one(&bytes);
        assert_eq!(hit.kind, Kind::Full);
        assert_eq!(hit.offset, 5);
        assert_eq!(hit.length, cert.len());
    }

    #[test]
    fn an_inner_length_past_the_body_is_not_a_hit() {
        let mut body = vec![0x30, 0x82, 0x02, 0x00];
        body.resize(0x100, 0);
        let mut bytes = vec![0x30, 0x82, 0x01, 0x00];
        bytes.extend_from_slice(&body);
        assert_eq!(bytes.len(), 4 + 0x100);
        assert!(scan(&bytes).is_empty());
    }

    #[test]
    fn adjacent_hits_do_not_overlap() {
        let cert = full_cert();
        let key = spki(300);
        let mut bytes = cert.clone();
        let split = bytes.len();
        bytes.extend_from_slice(&key);
        bytes.splice(0..0, [0x11, 0x22]);
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].kind, Kind::Full);
        assert_eq!(hits[0].offset, 2);
        assert_eq!(hits[0].length, cert.len());
        assert_eq!(hits[1].kind, Kind::Anchor);
        assert_eq!(hits[1].offset, 2 + split);
        assert_eq!(hits[1].length, key.len());
        assert!(hits[0].offset + hits[0].length <= hits[1].offset);
    }

    #[test]
    fn a_certificate_at_the_end_of_the_buffer_is_a_hit() {
        let cert = full_cert();
        let mut bytes = vec![0u8; 7];
        bytes.extend_from_slice(&cert);
        let hit = one(&bytes);
        assert_eq!(hit.offset, 7);
        assert_eq!(hit.offset + hit.length, bytes.len());
        assert_eq!(hit.kind, Kind::Full);
    }

    #[test]
    fn truncated_headers_yield_no_hit() {
        let samples: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x30, 0x81],
            &[0x30, 0x82],
            &[0x30, 0x82, 0x01],
            &[0x30, 0x82, 0x01, 0x00],
            &[0x30, 0x81, 0x80],
            &[0x30, 0x82, 0xff, 0xff],
        ];
        for bytes in samples {
            assert!(scan(bytes).is_empty(), "{bytes:02x?}");
        }
    }

    #[test]
    fn noise_yields_no_hit() {
        let samples = [
            vec![],
            vec![0u8; 3],
            vec![0x30, 0x82],
            vec![0x30, 0x81, 0xff],
            vec![0xff; 128],
            vec![0x30; 256],
        ];
        for bytes in samples {
            assert!(scan(&bytes).is_empty());
        }
    }

    #[test]
    fn the_library_fn_matches_scan() {
        let mut bytes = vec![0x00, 0x30];
        bytes.extend(full_cert());
        assert_eq!(crate::certs(&bytes), scan(&bytes));
    }
}
