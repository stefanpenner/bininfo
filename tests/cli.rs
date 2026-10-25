use std::fs;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bininfo"))
}

#[test]
fn prints_a_header() {
    let path = std::env::temp_dir().join(format!("elf-header-{}", std::process::id()));
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16] = 2;
    bytes[18] = 62;
    fs::write(&path, &bytes).unwrap();

    let out = bin().arg(&path).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("e_type: EXEC"), "{text}");
    assert!(text.contains("kind: static"), "{text}");
    assert!(text.contains("needed: []"), "{text}");
    assert!(!text.contains("hermetic:"), "{text}");
    assert!(!text.contains("says:"), "{text}");
    assert!(text.contains("undef: 0"), "{text}");
    assert!(text.contains("symtab: false"), "{text}");
    assert!(text.contains("entry_name: null"), "{text}");
    assert!(text.contains("\ntype:"), "{text}");
    assert!(text.contains("\nsizes:"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(
        text.contains("# 2 bytes. NONE, REL, EXEC, DYN, or CORE. The kernel runs EXEC and DYN."),
        "{text}"
    );
    assert!(!text.contains(r#""e_type""#), "{text}");

    let json = bin().arg("--json").arg(&path).output().unwrap();
    let json_text = String::from_utf8(json.stdout).unwrap();
    assert!(json.status.success(), "{json_text}");
    assert!(json_text.contains(r#""e_type":"EXEC""#), "{json_text}");
    assert!(json_text.contains(r#""kind":"static""#), "{json_text}");
    assert!(json_text.contains(r#""needed":[]"#), "{json_text}");
    assert!(!json_text.contains(r#""hermetic""#), "{json_text}");
    assert!(!json_text.contains(r#""says""#), "{json_text}");
    assert!(json_text.contains(r#""e_machine":62"#), "{json_text}");
    assert!(
        json_text.contains(r#""e_machine_name":"x86-64""#),
        "{json_text}"
    );
    assert!(json_text.contains(r#""entry_name":null"#), "{json_text}");
    assert!(
        json_text.contains(r#""symbols":{"undef":0,"defined":0,"symtab":false}"#),
        "{json_text}"
    );
    assert_eq!(json_text.matches('{').count(), 3, "{json_text}");

    let rows = bin().arg("--symbols").arg(&path).output().unwrap();
    let rows_text = String::from_utf8(rows.stdout).unwrap();
    assert!(
        rows.status.success(),
        "{}",
        String::from_utf8_lossy(&rows.stderr)
    );
    assert!(rows_text.contains("undef: []"), "{rows_text}");

    let _ = fs::remove_file(path);
}

#[test]
fn rejects_a_missing_path_and_a_non_elf() {
    let missing = bin().output().unwrap();
    assert!(!missing.status.success());
    let usage = String::from_utf8_lossy(&missing.stderr);
    assert!(
        usage.contains("usage: bininfo [--json] [--symbols] [--check] [--expect <claim>] <file>"),
        "{usage}"
    );
    assert!(usage.contains("--claims"), "{usage}");

    let path = std::env::temp_dir().join(format!("elf-header-bad-{}", std::process::id()));
    fs::write(&path, b"not elf").unwrap();
    let bad = bin().arg(&path).output().unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("not an ELF, Mach-O, or PE file"));
    let _ = fs::remove_file(path);
}

#[test]
fn prints_macho_and_pe_with_the_same_shape() {
    let macho = std::env::temp_dir().join(format!("elf-header-macho-{}", std::process::id()));
    let mut bytes = vec![0u8; 32];
    bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    bytes[4] = 0x0c;
    bytes[7] = 0x01;
    bytes[12] = 2;
    fs::write(&macho, &bytes).unwrap();
    let out = bin().arg(&macho).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("format: macho"), "{text}");
    assert!(text.contains("filetype: EXECUTE"), "{text}");
    assert!(text.contains("kind: static"), "{text}");
    assert!(text.contains("\ntype:"), "{text}");
    assert!(text.contains("\nload:"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    let json = bin().arg("--json").arg(&macho).output().unwrap();
    let json_text = String::from_utf8(json.stdout).unwrap();
    assert!(json_text.contains(r#""format":"macho""#), "{json_text}");
    assert!(json_text.contains(r#""kind":"static""#), "{json_text}");
    assert!(json_text.contains(r#""entry_name":null"#), "{json_text}");
    assert_eq!(json_text.matches('{').count(), 3, "{json_text}");
    let _ = fs::remove_file(macho);

    let pe = std::env::temp_dir().join(format!("elf-header-pe-{}", std::process::id()));
    let mut bytes = vec![0u8; 160];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c] = 64;
    bytes[64..68].copy_from_slice(b"PE\0\0");
    bytes[68] = 0x64;
    bytes[69] = 0x86;
    bytes[84] = 72;
    bytes[86] = 2;
    bytes[88] = 0x0b;
    bytes[89] = 0x02;
    fs::write(&pe, &bytes).unwrap();
    let out = bin().arg(&pe).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("format: pe"), "{text}");
    assert!(text.contains("class: PE32+"), "{text}");
    assert!(text.contains("kind: static"), "{text}");
    assert!(text.contains("\nload:"), "{text}");
    let json = bin().arg("--json").arg(&pe).output().unwrap();
    let json_text = String::from_utf8(json.stdout).unwrap();
    assert!(json_text.contains(r#""format":"pe""#), "{json_text}");
    assert!(json_text.contains(r#""kind":"static""#), "{json_text}");
    assert!(text.contains("os_version: 0.0"), "{text}");
    assert!(text.contains("subsystem_version: 0.0"), "{text}");
    assert_eq!(json_text.matches('{').count(), 3, "{json_text}");
    let _ = fs::remove_file(pe);
}

#[test]
fn check_accepts_a_closed_file_and_rejects_a_miss() {
    let path = std::env::temp_dir().join(format!("elf-header-check-{}", std::process::id()));
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16] = 2;
    bytes[18] = 62;
    fs::write(&path, &bytes).unwrap();

    let pass = bin().arg("--check").arg(&path).output().unwrap();
    let text = String::from_utf8(pass.stdout).unwrap();
    assert!(pass.status.success(), "{text}");
    assert!(text.contains("result: pass"), "{text}");
    assert!(text.contains("hermetic: true"), "{text}");
    assert!(text.contains("host:"), "{text}");
    assert!(text.contains("verneed: skip"), "{text}");
    assert!(text.contains("format: elf"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");

    let json = bin()
        .arg("--json")
        .arg("--check")
        .arg(&path)
        .output()
        .unwrap();
    let json_text = String::from_utf8(json.stdout).unwrap();
    assert!(json.status.success(), "{json_text}");
    assert!(json_text.contains(r#""result":"pass""#), "{json_text}");
    assert!(json_text.contains(r#""hermetic":true"#), "{json_text}");
    assert!(json_text.contains(r#""miss":[]"#), "{json_text}");
    assert!(json_text.contains(r#""verneed":"skip""#), "{json_text}");

    let fail = bin()
        .arg("--expect")
        .arg("kind=shared")
        .arg(&path)
        .output()
        .unwrap();
    let fail_text = String::from_utf8(fail.stdout).unwrap();
    assert!(!fail.status.success());
    assert!(
        fail.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&fail.stderr)
    );
    assert!(fail_text.contains("result: fail"), "{fail_text}");
    assert!(fail_text.contains("claim: kind=shared"), "{fail_text}");
    assert!(fail_text.contains("found: static"), "{fail_text}");

    let claims = std::env::temp_dir().join(format!("elf-header-claims-{}", std::process::id()));
    fs::write(
        &claims,
        format!(
            "# closed\n{} hermetic kind=static pie=false\n{} kind=rel\n",
            path.display(),
            path.display()
        ),
    )
    .unwrap();
    let many = bin().arg("--claims").arg(&claims).output().unwrap();
    let many_text = String::from_utf8(many.stdout).unwrap();
    assert!(!many.status.success());
    assert!(many_text.contains("result: pass"), "{many_text}");
    assert!(many_text.contains("result: fail"), "{many_text}");
    assert!(many_text.contains("\n---\n"), "{many_text}");

    let bad = bin()
        .arg("--expect")
        .arg("nope")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("unknown claim: nope"));

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(claims);
}

#[test]
fn flags_after_the_file_and_a_bom_comment_fail_closed() {
    let late = bin().arg("missing-binary").arg("--check").output().unwrap();
    let late_err = String::from_utf8_lossy(&late.stderr);
    assert!(!late.status.success());
    assert!(late_err.contains("usage: bininfo"), "{late_err}");
    assert!(!late_err.contains("cannot read"), "{late_err}");

    let after = bin()
        .arg("--claims")
        .arg("claims.txt")
        .arg("--json")
        .output()
        .unwrap();
    let after_err = String::from_utf8_lossy(&after.stderr);
    assert!(!after.status.success());
    assert!(after_err.contains("usage: bininfo"), "{after_err}");

    let symbols = bin()
        .arg("--symbols")
        .arg("--claims")
        .arg("claims.txt")
        .output()
        .unwrap();
    let symbols_err = String::from_utf8_lossy(&symbols.stderr);
    assert!(!symbols.status.success());
    assert!(symbols_err.contains("usage: bininfo"), "{symbols_err}");

    let bom = std::env::temp_dir().join(format!("bininfo-bom-{}", std::process::id()));
    fs::write(&bom, "\u{feff}# only a comment\n\u{200b}\n").unwrap();
    let comments = bin().arg("--claims").arg(&bom).output().unwrap();
    let comments_err = String::from_utf8_lossy(&comments.stderr);
    assert!(!comments.status.success());
    assert!(comments_err.contains("no file"), "{comments_err}");
    assert!(!comments_err.contains("unknown claim"), "{comments_err}");
    let _ = fs::remove_file(bom);
}

#[test]
fn a_fat_macho_opens_each_slice() {
    let path = std::env::temp_dir().join(format!("elf-header-fat-{}", std::process::id()));
    let mut x86 = vec![0u8; 32];
    x86[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    x86[4] = 0x07;
    x86[7] = 0x01;
    x86[12] = 2;
    let mut arm = vec![0u8; 32];
    arm[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    arm[4] = 0x0c;
    arm[7] = 0x01;
    arm[12] = 2;
    arm[24] = 0x00;
    arm[25] = 0x00;
    arm[26] = 0x20;
    let mut bytes = vec![0u8; 48];
    bytes[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    bytes[7] = 2;
    bytes[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
    bytes[11] = 0x07;
    bytes[15] = 3;
    bytes[16..20].copy_from_slice(&48u32.to_be_bytes());
    bytes[20..24].copy_from_slice(&32u32.to_be_bytes());
    bytes[28..32].copy_from_slice(&0x0100_000cu32.to_be_bytes());
    bytes[35] = 2;
    bytes[36..40].copy_from_slice(&80u32.to_be_bytes());
    bytes[40..44].copy_from_slice(&32u32.to_be_bytes());
    bytes.extend_from_slice(&x86);
    bytes.extend_from_slice(&arm);
    fs::write(&path, &bytes).unwrap();

    let out = bin().arg(&path).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("magic: 0xCAFEBABE"), "{text}");
    assert!(text.contains("universal: universal2"), "{text}");
    assert!(text.contains("cputype_name: x86-64 (16777223)"), "{text}");
    assert!(text.contains("cpusubtype_name: ARM64E (2)"), "{text}");
    assert!(text.contains("kind: static"), "{text}");
    assert!(text.contains("kind: static-pie"), "{text}");
    assert!(!text.contains("This page does not open a slice."), "{text}");
    assert!(
        text.contains("These slices do not share one load."),
        "{text}"
    );

    let json = bin().arg("--json").arg(&path).output().unwrap();
    let json_text = String::from_utf8(json.stdout).unwrap();
    assert!(
        json_text.contains(r#""universal":"universal2""#),
        "{json_text}"
    );
    assert!(
        json_text.contains(r#""cputype_name":"x86-64""#),
        "{json_text}"
    );
    assert!(
        json_text.contains(r#""cpusubtype_name":"ARM64E""#),
        "{json_text}"
    );
    assert!(json_text.contains(r#""kind":"static""#), "{json_text}");
    assert!(json_text.contains(r#""kind":"static-pie""#), "{json_text}");
    assert!(
        !json_text.contains(r#""load":{"kind":"other""#),
        "{json_text}"
    );

    let check = bin().arg("--check").arg(&path).output().unwrap();
    let check_text = String::from_utf8(check.stdout).unwrap();
    assert!(check.status.success(), "{check_text}");
    assert!(check_text.contains("hermetic: true"), "{check_text}");
    assert!(!check_text.contains("says:"), "{check_text}");
    let _ = fs::remove_file(path);
}

fn padded_bundle(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let pem = std::path::Path::new("tests/fixtures/probe-bundle.pem").to_path_buf();
    let mut bytes = vec![0u8; 2048];
    bytes.extend(fs::read(&pem).unwrap());
    let path = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    fs::write(&path, bytes).unwrap();
    (path, pem)
}

#[test]
fn features_lists_certs_and_match() {
    let out = bin().arg("--features").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success());
    assert!(text.lines().any(|l| l == "certs"), "{text}");
    assert!(text.lines().any(|l| l == "match"), "{text}");
}

#[test]
fn certs_json_has_a_version_and_a_list() {
    let (path, _) = padded_bundle("certs-json");
    let out = bin().args(["--certs", "--json"]).arg(&path).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{text}");
    assert!(text.starts_with(r#"{"version":1,"file":""#), "{text}");
    assert!(text.contains(r#""certs":[{"#), "{text}");
    assert_eq!(text.lines().count(), 1, "{text}");
}

#[test]
fn match_keeps_only_matches_and_exits_1() {
    let (path, pem) = padded_bundle("certs-match");
    let hit = bin().args(["--certs", "--json", "--match"]).arg(&pem).arg(&path).output().unwrap();
    let text = String::from_utf8(hit.stdout).unwrap();
    assert_eq!(hit.status.code(), Some(1), "{text}");
    assert!(text.contains(r#""matched_by":"sha256""#), "{text}");

    let miss = bin()
        .args(["--certs", "--json", "--match-cn", "No Such CA"])
        .arg(&path)
        .output()
        .unwrap();
    let text = String::from_utf8(miss.stdout).unwrap();
    assert_eq!(miss.status.code(), Some(0), "{text}");
    assert!(text.contains(r#""certs":[]"#), "{text}");
}

#[test]
fn match_without_certs_is_a_usage_error() {
    let out = bin().args(["--match-cn", "x", "/bin/ls"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}
