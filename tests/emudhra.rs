/*
---
why: This file checks the eMudhra policy against public fixtures.
uses: cargo test
how: cargo test scans each fixture with the distrusted policy.
---
*/

//! Each fixture is cited in tests/fixtures/emudhra/sources.txt.
//! The check date is 2026-10-24.

use bininfo::certs::{self, Container, Encoding, Hit, Kind};
use bininfo::policy::{self, Report, Severity};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const POLICY: &str = include_str!("../policies/distrusted.policy");

const KEYS: &[(&str, &str)] = &[
    (
        "em-dv-tls-g3b",
        "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
    ),
    (
        "em-ov-tls-g3b",
        "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
    ),
    (
        "em-ev-tls-g3b",
        "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
    ),
    (
        "em-dv-tls-g3c",
        "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
    ),
    (
        "em-ov-tls-g3c",
        "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
    ),
    (
        "em-ev-tls-g3c",
        "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
    ),
    (
        "em-ov-cs-g3b",
        "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
    ),
    (
        "em-ov-cs-g3c",
        "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
    ),
];

fn suite() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/emudhra")
}

fn read(rel: &str) -> Vec<u8> {
    let path = suite().join(rel);
    fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn judge(bytes: &[u8]) -> Report {
    bininfo::check_policy(bytes, POLICY).unwrap()
}

fn ids(report: &Report, severity: Severity) -> BTreeSet<String> {
    report
        .violations
        .iter()
        .filter(|item| item.severity == severity)
        .map(|item| item.id.clone())
        .collect()
}

fn denies(report: &Report) -> BTreeSet<String> {
    ids(report, Severity::Deny)
}

fn warns(report: &Report) -> BTreeSet<String> {
    ids(report, Severity::Warn)
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|id| (*id).to_string()).collect()
}

fn fulls(bytes: &[u8]) -> Vec<Hit> {
    certs::scan(bytes)
        .into_iter()
        .filter(|hit| hit.kind == Kind::Full)
        .collect()
}

fn one_full(bytes: &[u8], label: &str) -> Hit {
    let hits = fulls(bytes);
    assert_eq!(hits.len(), 1, "{label} hits {}", hits.len());
    hits.into_iter().next().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn chain_slug(name: &str) -> &'static str {
    if name.starts_with("dv-g3b") {
        "em-dv-tls-g3b"
    } else if name.starts_with("dv-g3c") {
        "em-dv-tls-g3c"
    } else if name.starts_with("ov-g3b") {
        "em-ov-tls-g3b"
    } else if name.starts_with("ov-g3c") {
        "em-ov-tls-g3c"
    } else if name.starts_with("ev-g3b") {
        "em-ev-tls-g3b"
    } else if name.starts_with("ev-g3c") {
        "em-ev-tls-g3c"
    } else {
        panic!("unexpected chain {name}")
    }
}

fn zeek_slug(name: &str) -> String {
    name.trim_start_matches("zeek-testing-")
        .trim_end_matches(".pem")
        .replace("-ca-", "-")
}

#[test]
fn each_intermediate_encoding_is_denied_by_spki() {
    let forms = [
        ("der", Encoding::Der, Container::File),
        ("pem", Encoding::Pem, Container::File),
        ("b64", Encoding::Base64, Container::File),
        ("gz", Encoding::Der, Container::Gzip),
        ("zip", Encoding::Der, Container::Zip),
    ];
    for (slug, spki) in KEYS {
        for (ext, encoding, container) in forms {
            let label = format!("intermediates/{slug}.{ext}");
            let bytes = read(&label);
            let hit = one_full(&bytes, &label);
            assert_eq!(hit.encoding, encoding, "{label}");
            assert_eq!(hit.container, container, "{label}");
            assert_eq!(hex(&hit.spki_sha256), *spki, "{label}");
            let report = judge(&bytes);
            assert!(report.failed(), "{label}");
            assert_eq!(denies(&report), set(&[slug]), "{label}");
            assert!(warns(&report).is_empty(), "{label}");
        }
    }
}

#[test]
fn each_sectigo_cross_sign_keeps_the_spki_and_changes_the_hash() {
    for (slug, spki) in KEYS {
        let left = one_full(&read(&format!("intermediates/{slug}.der")), slug);
        let label = format!("sectigo/{slug}.der");
        let right = one_full(&read(&label), &label);
        assert_eq!(hex(&left.spki_sha256), *spki, "{label}");
        assert_eq!(right.spki_sha256, left.spki_sha256, "{label}");
        assert_ne!(right.sha256, left.sha256, "{label}");
        let report = judge(&read(&label));
        assert!(report.failed(), "{label}");
        assert_eq!(denies(&report), set(&[slug]), "{label}");
        assert!(warns(&report).is_empty(), "{label}");
        let pem = judge(&read(&format!("sectigo/{slug}.pem")));
        assert_eq!(denies(&pem), set(&[slug]), "sectigo/{slug}.pem");
    }
}

#[test]
fn a_high_s_reencoding_changes_the_hash_and_keeps_the_spki() {
    let orig = one_full(&read("intermediates/em-dv-tls-g3b.der"), "original");
    let bytes = read("malleable/em-dv-tls-g3b-high-s.der");
    let hit = one_full(&bytes, "high-s");
    assert_ne!(hit.sha256, orig.sha256);
    assert_eq!(hit.spki_sha256, orig.spki_sha256);
    assert_eq!(
        hex(&hit.spki_sha256),
        "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105"
    );
    let report = judge(&bytes);
    assert!(report.failed());
    assert_eq!(denies(&report), set(&["em-dv-tls-g3b"]));
    assert!(warns(&report).is_empty());
    let sha_only = format!("deny one sha256 {} :: one encoding\n", hex(&orig.sha256));
    assert!(!bininfo::check_policy(&bytes, &sha_only).unwrap().failed());
    let spki_only = format!("deny one spki {} :: the key\n", hex(&orig.spki_sha256));
    assert!(bininfo::check_policy(&bytes, &spki_only).unwrap().failed());
}

#[test]
fn a_test_leaf_is_flagged_with_and_without_the_intermediate() {
    let cases = [
        (
            "leaves/example-test-ov-tls-g3c.pem",
            "leaves/example-test-ov-tls-g3c-chain.pem",
            "issuer-em-ov-tls-g3c",
            "em-ov-tls-g3c",
        ),
        (
            "leaves/example-test-ov-cs-g3b.pem",
            "leaves/example-test-ov-cs-g3b-chain.pem",
            "issuer-em-ov-cs-g3b",
            "em-ov-cs-g3b",
        ),
    ];
    for (alone_path, chain_path, issuer, spki) in cases {
        let alone_bytes = read(alone_path);
        let alone_hit = one_full(&alone_bytes, alone_path);
        assert_eq!(alone_hit.subject_cn.as_deref(), Some("example.test"));
        assert!(alone_bytes
            .windows(b"example.com".len())
            .all(|w| w != b"example.com"));
        let alone = judge(&alone_bytes);
        assert_eq!(denies(&alone), set(&[issuer]), "{alone_path}");
        assert!(warns(&alone).is_empty(), "{alone_path}");
        let chain_bytes = read(chain_path);
        assert_eq!(fulls(&chain_bytes).len(), 2, "{chain_path}");
        let chain = judge(&chain_bytes);
        assert_eq!(denies(&chain), set(&[issuer, spki]), "{chain_path}");
        assert!(warns(&chain).is_empty(), "{chain_path}");
    }
}

#[test]
fn roots_are_denied_or_warned_by_spki() {
    let cases = [
        ("roots/emsign-ecc-g3.pem", Some("emsign-ecc-g3"), None),
        (
            "roots/emsign-root-tls-g3.pem",
            None,
            Some("emsign-root-tls-g3"),
        ),
        (
            "roots/emsign-root-cs-g3.pem",
            None,
            Some("emsign-root-cs-g3"),
        ),
        ("roots/sectigo-aaa.pem", None, Some("sectigo-aaa")),
    ];
    for (path, deny, warn) in cases {
        let report = judge(&read(path));
        let expect_deny = deny.map(|id| set(&[id])).unwrap_or_default();
        let expect_warn = warn.map(|id| set(&[id])).unwrap_or_default();
        assert_eq!(denies(&report), expect_deny, "{path}");
        assert_eq!(warns(&report), expect_warn, "{path}");
        assert_eq!(report.failed(), deny.is_some(), "{path}");
    }
}

#[test]
fn the_old_curl_bundle_fails_and_the_new_bundle_passes() {
    let old_bytes = read("bundles/cacert-2026-09-25.pem");
    let new_bytes = read("bundles/cacert-2026-10-20.pem");
    let old_names = cns(&old_bytes);
    let new_names = cns(&new_bytes);
    for name in [
        "emSign Root CA - G1",
        "emSign Root CA - C1",
        "emSign ECC Root CA - C3",
        "emSign ECC Root CA - G3",
    ] {
        assert!(old_names.contains(name), "{name}");
    }
    assert!(new_names.contains("emSign Root CA - G1"));
    assert!(!new_names.contains("emSign ECC Root CA - G3"));
    let old = judge(&old_bytes);
    let new = judge(&new_bytes);
    assert_eq!(denies(&old), set(&["emsign-ecc-g3"]));
    assert!(old.failed());
    assert!(denies(&new).is_empty());
    assert!(!new.failed());
}

#[test]
fn safe_emudhra_certificates_are_not_denied() {
    let dir = suite().join("negative");
    let mut seen = BTreeSet::new();
    for path in files(&dir) {
        let name = file_name(&path);
        seen.insert(name.clone());
        let bytes = fs::read(&path).unwrap();
        let hits = fulls(&bytes);
        assert!(!hits.is_empty(), "{name}");
        let report = judge(&bytes);
        assert!(denies(&report).is_empty(), "{name} {:?}", denies(&report));
        assert!(warns(&report).is_empty(), "{name} {:?}", warns(&report));
        assert!(!report.failed(), "{name}");
    }
    assert!(seen.contains("emsign-root-ca-g1.pem"));
    assert!(seen.contains("emsign-root-ca-c1.pem"));
    assert!(seen.contains("emsign-ecc-root-ca-c3.pem"));
    assert!(seen.contains("em-dv-tls-g2a.pem"));
    assert!(seen.contains("emsign-root-tls-ca-g1.pem"));
    assert!(seen.contains("emsign-root-tls-ca-g1-cross.pem"));
    let g2a = one_full(&read("negative/em-dv-tls-g2a.pem"), "g2a");
    assert_eq!(g2a.subject_cn.as_deref(), Some("EM DV TLS CA - G2A"));
    assert_eq!(g2a.issuer_cn.as_deref(), Some("emSign Root TLS CA - G1"));
    let cross = one_full(
        &read("negative/emsign-root-tls-ca-g1-cross.pem"),
        "g1 cross",
    );
    assert_eq!(cross.subject_cn.as_deref(), Some("emSign Root TLS CA - G1"));
    assert_eq!(cross.issuer_cn.as_deref(), Some("emSign Root CA - G1"));
}

#[test]
fn public_chains_and_corelight_fixtures_match_the_policy() {
    let mut chains = 0;
    for path in files(&suite().join("chains")) {
        let name = file_name(&path);
        chains += 1;
        let bytes = fs::read(&path).unwrap();
        let slug = chain_slug(&name);
        let report = judge(&bytes);
        assert_eq!(
            denies(&report),
            set(&[slug, &format!("issuer-{slug}")]),
            "{name}"
        );
        if name.contains("-aaa-") {
            assert_eq!(fulls(&bytes).len(), 2, "{name}");
            assert!(warns(&report).is_empty(), "{name}");
        } else {
            assert_eq!(fulls(&bytes).len(), 3, "{name}");
            assert_eq!(warns(&report), set(&["emsign-root-tls-g3"]), "{name}");
            assert!(!denies(&report).contains("emsign-ecc-g3"), "{name}");
        }
    }
    assert_eq!(chains, 14);

    let mut zeek = 0;
    for path in files(&suite().join("corelight")) {
        let name = file_name(&path);
        let bytes = fs::read(&path).unwrap();
        let report = judge(&bytes);
        if name == "emudhra-1.pcap" {
            assert_eq!(fulls(&bytes).len(), 2);
            assert_eq!(
                denies(&report),
                set(&["em-ov-tls-g3c", "issuer-em-ov-tls-g3c"])
            );
            assert!(warns(&report).is_empty());
        } else if name == "emsign-root-tls-g3-cross-signed.pem" {
            let hit = one_full(&bytes, &name);
            let root = one_full(&read("roots/emsign-root-tls-g3.pem"), "tls root");
            assert_eq!(hit.spki_sha256, root.spki_sha256);
            assert_ne!(hit.sha256, root.sha256);
            assert!(denies(&report).is_empty());
            assert_eq!(warns(&report), set(&["emsign-root-tls-g3"]));
            assert!(!report.failed());
        } else if name.starts_with("zeek-testing-") {
            zeek += 1;
            let slug = zeek_slug(&name);
            assert_eq!(fulls(&bytes).len(), 1, "{name}");
            assert_eq!(denies(&report), set(&[&format!("issuer-{slug}")]), "{name}");
            assert!(warns(&report).is_empty(), "{name}");
        } else {
            panic!("unexpected corelight file {name}");
        }
    }
    assert_eq!(zeek, 7);
}

fn cns(bytes: &[u8]) -> BTreeSet<String> {
    fulls(bytes)
        .into_iter()
        .filter_map(|hit| hit.subject_cn)
        .collect()
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|item| item.unwrap().path())
        .filter(|path| path.is_file())
        .collect();
    out.sort();
    out
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}
