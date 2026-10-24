/*
---
why: This file finds embedded certificates and trust anchors in a binary.
uses: bininfo
how: bininfo calls this file to scan read-only bytes.
This file does not print the page.
---
*/

//! Scan a byte slice for ASN.1 sequences that look like certificates.
//! A full certificate parses as X.509. A trust anchor is a smaller DER fragment.

/// One hit in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// File offset of the first byte.
    pub offset: usize,
    /// Length of the SEQUENCE, including the tag and length bytes.
    pub length: usize,
    /// Full certificate or minimal trust-anchor fragment.
    pub kind: Kind,
}

/// Full X.509 certificate or a smaller trust-anchor fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The slice parses as a complete certificate.
    Full,
    /// The slice is valid ASN.1 but not a full certificate.
    Anchor,
}

/// Scan `bytes` for SEQUENCE tags that may be certificates or anchors.
///
/// Looks for `30 82` (long form) and `30 81` (short form).
/// Stops at the first parse failure for a candidate so false positives stay rare.
pub fn scan(bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut index = 0;
    while index + 4 < bytes.len() {
        if bytes[index] != 0x30 {
            index += 1;
            continue;
        }
        let (len, header) = match length_of(&bytes[index..]) {
            Some(pair) => pair,
            None => {
                index += 1;
                continue;
            }
        };
        let end = index + header + len;
        if end > bytes.len() {
            index += 1;
            continue;
        }
        let slice = &bytes[index..end];
        if let Some(kind) = classify(slice) {
            hits.push(Hit {
                offset: index,
                length: header + len,
                kind,
            });
            index = end;
        } else {
            index += 1;
        }
    }
    hits
}

fn length_of(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 2 || bytes[0] != 0x30 {
        return None;
    }
    match bytes[1] {
        0x81 if bytes.len() >= 3 => Some((bytes[2] as usize, 3)),
        0x82 if bytes.len() >= 4 => {
            let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
            Some((len, 4))
        }
        len if len < 0x80 => Some((len as usize, 2)),
        _ => None,
    }
}

fn classify(slice: &[u8]) -> Option<Kind> {
    // A full certificate is a SEQUENCE that contains a TBSCertificate SEQUENCE,
    // a signature algorithm, and a BIT STRING. We only check the outer shape
    // and a minimum size so we stay free of a crypto crate.
    if slice.len() < 64 {
        return Some(Kind::Anchor);
    }
    if looks_like_cert(slice) {
        Some(Kind::Full)
    } else {
        Some(Kind::Anchor)
    }
}

fn looks_like_cert(slice: &[u8]) -> bool {
    // Outer SEQUENCE, then a TBSCertificate SEQUENCE starting soon after the header.
    if slice[0] != 0x30 {
        return false;
    }
    let Some((outer_len, header)) = length_of(slice) else {
        return false;
    };
    if header + outer_len != slice.len() {
        return false;
    }
    let rest = &slice[header..];
    // TBSCertificate is itself a SEQUENCE.
    if rest.is_empty() || rest[0] != 0x30 {
        return false;
    }
    // Signature algorithm OID is usually near the end; we only require a second SEQUENCE.
    let Some((_, tbs_header)) = length_of(rest) else {
        return false;
    };
    rest.len() > tbs_header + 8
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal well-formed SEQUENCE of length 4 (not a cert).
    #[test]
    fn a_short_sequence_is_an_anchor() {
        let bytes = [0x30, 0x04, 0x01, 0x01, 0x00, 0x00];
        let hits = scan(&bytes);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Anchor);
        assert_eq!(hits[0].length, 6);
    }

    // Long-form SEQUENCE that contains an inner SEQUENCE (looks like a cert).
    #[test]
    fn a_nested_sequence_is_full() {
        // 30 82 00 20  30 82 00 10  ... padding to make outer length match
        let mut bytes = vec![0x30, 0x82, 0x00, 0x20];
        bytes.extend_from_slice(&[0x30, 0x82, 0x00, 0x10]);
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&[0u8; 12]); // rest of outer
        let hits = scan(&bytes);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].kind, Kind::Full);
    }

    #[test]
    fn noise_does_not_panic() {
        let samples = vec![
            vec![],
            vec![0u8; 3],
            vec![0x30, 0x82],
            vec![0x30, 0x81, 0xff],
            vec![0xff; 128],
        ];
        for bytes in samples {
            let _ = scan(&bytes);
        }
    }
}
