use std::fs;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_elf-header"))
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
    assert!(text.contains("e_type       EXEC"), "{text}");
    assert!(text.contains("e_machine    x86-64 (62)"), "{text}");

    let _ = fs::remove_file(path);
}

#[test]
fn rejects_a_missing_path_and_a_non_elf() {
    let missing = bin().output().unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("usage: elf-header <file>"));

    let path = std::env::temp_dir().join(format!("elf-header-bad-{}", std::process::id()));
    fs::write(&path, b"not elf").unwrap();
    let bad = bin().arg(&path).output().unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("not an ELF file"));
    let _ = fs::remove_file(path);
}
