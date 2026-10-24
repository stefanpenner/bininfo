/*
---
why: This file scans one file for embedded certificates.
uses: bininfo
how: A person runs this example on a file path.
The example prints hit counts.
---
*/

use bininfo::certs::Container;
use bininfo::certs::Encoding;
use bininfo::certs::Kind;
use bininfo::certs::Role;

const EMSIGN: [u8; 32] = [
    0x86, 0xa1, 0xec, 0xba, 0x08, 0x9c, 0x4a, 0x8d, 0x3b, 0xbe, 0x27, 0x34, 0xc6, 0x12, 0xba, 0x34,
    0x1d, 0x81, 0x3e, 0x04, 0x3c, 0xf9, 0xe8, 0xa8, 0x62, 0xcd, 0x5c, 0x57, 0xa3, 0x6b, 0xbe, 0x6b,
];

const EMSIGN_SPKI: [u8; 32] = [
    0x8d, 0x41, 0x7d, 0xb2, 0xdd, 0x8b, 0xf5, 0xe3, 0x08, 0x4d, 0x1e, 0x3f, 0x19, 0x6d, 0x58, 0x38,
    0x49, 0xd8, 0x1b, 0xdd, 0x4c, 0x00, 0xc7, 0x0b, 0x9d, 0x39, 0x36, 0x9e, 0x96, 0xb8, 0xc7, 0x82,
];

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: certs <file>");
        std::process::exit(2);
    }
    for path in paths {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("{path}: {err}");
                std::process::exit(1);
            }
        };
        let hits = bininfo::certs(&bytes);
        let mut full = 0;
        let mut anchor = 0;
        let mut body = 0;
        let mut pin = 0;
        let mut der = 0;
        let mut pem = 0;
        let mut base64 = 0;
        let mut gzip = 0;
        let mut zlib = 0;
        let mut zip = 0;
        let mut sea = 0;
        let mut signer = 0;
        let mut emsign = 0;
        let mut emsign_spki = 0;
        for hit in &hits {
            match hit.kind {
                Kind::Full => full += 1,
                Kind::Anchor => anchor += 1,
                Kind::Body => body += 1,
                Kind::Pin => pin += 1,
            }
            match hit.encoding {
                Encoding::Der => der += 1,
                Encoding::Pem => pem += 1,
                Encoding::Base64 => base64 += 1,
            }
            match hit.container {
                Container::File => {}
                Container::Gzip => gzip += 1,
                Container::Zlib => zlib += 1,
                Container::Zip => zip += 1,
                Container::Sea => sea += 1,
            }
            if hit.role == Role::Signer {
                signer += 1;
            }
            if hit.kind != Kind::Pin && hit.sha256 == EMSIGN {
                emsign += 1;
            }
            if hit.kind != Kind::Pin && hit.spki_sha256 == EMSIGN_SPKI {
                emsign_spki += 1;
            }
        }
        println!(
            "{path} full={full} anchor={anchor} body={body} pin={pin} der={der} pem={pem} base64={base64} gzip={gzip} zlib={zlib} zip={zip} sea={sea} signer={signer} emsign={emsign} emsign_spki={emsign_spki} bytes={}",
            bytes.len()
        );
    }
}
