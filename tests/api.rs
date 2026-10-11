/*
---
why: This file checks that another crate can call the library.
uses: cargo test
how: cargo test builds this file against the bininfo library.
The test does not run the bininfo command.
---
*/

use bininfo::claim::Host;
use bininfo::kind::{self, Kind};

fn host() -> Host {
    Host {
        arch: "aarch64",
        os: "macos",
        version: None,
        pac: true,
    }
}

fn static_elf() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16] = 2;
    bytes[18] = 62;
    bytes
}

#[test]
fn a_caller_opens_one_elf_and_checks_a_claim() {
    let bytes = static_elf();
    assert!(bininfo::elf::header::is_elf(&bytes));
    assert!(!bininfo::macho::header::is_macho(&bytes));
    assert!(!bininfo::pe::header::is_pe(&bytes));

    let file = bininfo::open(&bytes, false).unwrap();
    match &file {
        bininfo::Binary::Elf { load, .. } => assert_eq!(load.kind, Kind::Static),
        _ => panic!("expected an ELF file"),
    }
    let page = bininfo::render("tiny", &file, false, false);
    assert!(page.contains("kind: static"), "{page}");
    assert!(page.contains("format: elf"), "{page}");

    let json = bininfo::render("tiny", &file, true, false);
    assert!(json.contains(r#""kind":"static""#), "{json}");

    let facts = bininfo::facts("tiny", &file, &host());
    assert_eq!(facts.kind, Kind::Static);
    assert_eq!(kind::name(facts.kind), "static");
    let claims = bininfo::claim::parse(&["hermetic".to_string()]).unwrap();
    let misses = bininfo::claim::judge(&facts, &claims);
    assert!(misses.is_empty(), "{misses:?}");
}
