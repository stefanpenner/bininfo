//! Read an ELF file header and print it.

mod header;

use std::env;
use std::fs::File;
use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let path = args.next().ok_or("usage: elf-header <file>")?;
    if args.next().is_some() {
        return Err("usage: elf-header <file>".into());
    }
    let bytes = read_prefix(&path, 64)?;
    let header = header::parse(&bytes)?;
    print!("{header}");
    Ok(())
}

fn read_prefix(path: &str, limit: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("cannot read {path}: {err}"))?;
    Ok(bytes)
}
