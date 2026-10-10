use std::fs;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_herman"))
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
    assert!(text.contains("hermetic: true"), "{text}");
    assert!(
        text.contains("says: This program starts itself and names no other file."),
        "{text}"
    );
    assert!(text.contains("\ntype:"), "{text}");
    assert!(text.contains("\nsizes:"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(
        text.contains("# 2 bytes. The kernel runs EXEC and DYN."),
        "{text}"
    );
    assert!(!text.contains(r#""e_type""#), "{text}");

    let json = bin().arg("--json").arg(&path).output().unwrap();
    let json_text = String::from_utf8(json.stdout).unwrap();
    assert!(json.status.success(), "{json_text}");
    assert!(json_text.contains(r#""e_type":"EXEC""#), "{json_text}");
    assert!(json_text.contains(r#""kind":"static""#), "{json_text}");
    assert!(json_text.contains(r#""needed":[]"#), "{json_text}");
    assert!(json_text.contains(r#""hermetic":true"#), "{json_text}");
    assert!(
        json_text.contains(r#""says":"This program starts itself and names no other file.""#),
        "{json_text}"
    );
    assert!(json_text.contains(r#""e_machine":62"#), "{json_text}");
    assert!(
        json_text.contains(r#""e_machine_name":"x86-64""#),
        "{json_text}"
    );
    assert_eq!(json_text.matches('{').count(), 2, "{json_text}");

    let _ = fs::remove_file(path);
}

#[test]
fn rejects_a_missing_path_and_a_non_elf() {
    let missing = bin().output().unwrap();
    assert!(!missing.status.success());
    let usage = String::from_utf8_lossy(&missing.stderr);
    assert!(
        usage.contains("usage: herman [--json] [--check] [--expect <claim>] <file>"),
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
    assert_eq!(json_text.matches('{').count(), 2, "{json_text}");
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
    assert_eq!(json_text.matches('{').count(), 2, "{json_text}");
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
