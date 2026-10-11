//! Read an ELF, Mach-O, or PE header and print it.
//! `--check` asks whether the header names no other file.

mod claim;
mod elf;
mod kind;
mod macho;
mod pe;
mod style;

use std::env;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;

const USAGE: &str = "\
usage: binvet [--json] [--symbols] [--check] [--expect <claim>] <file>
usage: binvet [--json] --claims <file>";

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

enum Job {
    Show {
        path: String,
        json: bool,
        symbols: bool,
    },
    Check {
        path: String,
        json: bool,
        expect: Vec<String>,
    },
    Claims {
        path: String,
        json: bool,
    },
}

enum Opened {
    Elf {
        header: elf::header::Header,
        load: elf::load::Load,
        symbols: elf::symbols::Symbols,
    },
    Macho {
        image: macho::header::Image,
        commands: macho::load::Commands,
        slices: Vec<macho::load::Slice>,
    },
    Pe {
        header: pe::header::Header,
        load: pe::load::Load,
        symbols: pe::symbols::Symbols,
    },
}

fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    match args_of(args)? {
        Job::Show {
            path,
            json,
            symbols,
        } => {
            let bytes = read_file(&path)?;
            print!("{}", render(&path, &bytes, json, symbols)?);
            Ok(ExitCode::SUCCESS)
        }
        Job::Check { path, json, expect } => {
            let tokens = if expect.is_empty() {
                vec!["hermetic".to_string()]
            } else {
                expect
            };
            let claims = claim::parse(&tokens)?;
            check_one(&path, &claims, json)
        }
        Job::Claims { path, json } => check_file(&path, json),
    }
}

fn render(path: &str, bytes: &[u8], json: bool, symbols: bool) -> Result<String, String> {
    let color = color_stdout();
    match open(bytes, symbols)? {
        Opened::Elf {
            header,
            load,
            symbols,
        } => Ok(if json {
            elf::json::render_with(path, &header, &load, &symbols)
        } else {
            elf::page::render_with(path, &header, &load, &symbols, color)
        }),
        Opened::Macho {
            image,
            commands,
            slices,
        } => Ok(if json {
            macho::json::render(path, &image, &commands, &slices)
        } else {
            macho::page::render(path, &image, &commands, &slices, color)
        }),
        Opened::Pe {
            header,
            load,
            symbols,
        } => Ok(if json {
            pe::json::render_with(path, &header, &load, &symbols)
        } else {
            pe::page::render_with(path, &header, &load, &symbols, color)
        }),
    }
}

fn open(bytes: &[u8], rows: bool) -> Result<Opened, String> {
    if elf::header::is_elf(bytes) {
        let header = elf::header::parse(bytes)?;
        let load = elf::load::read(bytes, &header);
        let symbols = elf::symbols::read(bytes, &header, rows);
        return Ok(Opened::Elf {
            header,
            load,
            symbols,
        });
    }
    if macho::header::is_macho(bytes) {
        let image = macho::header::parse(bytes)?;
        let slices = macho::load::slices_rows(bytes, &image, rows);
        let commands = match &image {
            macho::header::Image::Fat(_) => macho::load::commands_for(&slices),
            macho::header::Image::Thin(_) => macho::load::read_at(bytes, &image, rows),
        };
        return Ok(Opened::Macho {
            image,
            commands,
            slices,
        });
    }
    if pe::header::is_pe(bytes) {
        let header = pe::header::parse(bytes)?;
        let load = pe::load::read(bytes, &header);
        let symbols = pe::symbols::read(bytes, &header, rows);
        return Ok(Opened::Pe {
            header,
            load,
            symbols,
        });
    }
    Err("not an ELF, Mach-O, or PE file".into())
}

fn facts_of(file: &str, bytes: &[u8]) -> Result<claim::Facts, String> {
    let host = this_host();
    Ok(match open(bytes, false)? {
        Opened::Elf {
            header,
            load,
            symbols,
        } => claim::Facts {
            file: file.to_string(),
            format: "elf",
            kind: load.kind,
            interp: load.interp,
            needed: load.needed,
            pie: load.pie,
            fat_hermetic: None,
            host: claim::host_marks(&elf::symbols::floors(&header, &symbols), &host),
        },
        Opened::Macho {
            image,
            commands,
            slices,
        } => {
            let host =
                claim::host_marks(&macho::symbols::floors(&image, &commands, &slices), &host);
            claim::Facts {
                file: file.to_string(),
                format: "macho",
                kind: commands.load.kind,
                interp: commands.load.interp,
                needed: commands.load.needed,
                pie: commands.load.pie,
                fat_hermetic: macho::load::fat_hermetic(&slices),
                host,
            }
        }
        Opened::Pe {
            header,
            load,
            symbols,
        } => claim::Facts {
            file: file.to_string(),
            format: "pe",
            kind: load.kind,
            interp: load.interp,
            needed: load.needed,
            pie: load.pie,
            fat_hermetic: None,
            host: claim::host_marks(&pe::symbols::floors(&header, &symbols), &host),
        },
    })
}

fn this_host() -> claim::Host {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let version = match os {
        "macos" => command_version("sw_vers", &["-productVersion"]),
        "linux" => command_version("uname", &["-r"]),
        _ => None,
    };
    claim::Host {
        arch,
        os,
        version,
        pac: os == "macos" && arch == "aarch64",
    }
}

fn command_version(bin: &str, args: &[&str]) -> Option<claim::Version> {
    let out = std::process::Command::new(bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    claim::parse_version(text.trim())
}

fn check_one(path: &str, claims: &[claim::Claim], json: bool) -> Result<ExitCode, String> {
    let bytes = read_file(path)?;
    let facts = facts_of(path, &bytes)?;
    let misses = claim::judge(&facts, claims);
    print_report(&facts, &misses, json);
    Ok(code_of(&misses))
}

fn check_file(path: &str, json: bool) -> Result<ExitCode, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let mut code = ExitCode::SUCCESS;
    let mut count = 0usize;
    let mut first = true;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        count += 1;
        let mut parts = line.split_whitespace();
        let file = parts.next().expect("a trimmed line has a token");
        let tokens: Vec<String> = parts.map(str::to_string).collect();
        let claims = claim::parse(&tokens).map_err(|err| format!("{path}:{}: {err}", index + 1))?;
        let claims = if claims.is_empty() {
            claim::parse(&["hermetic".to_string()])?
        } else {
            claims
        };
        let bytes = match read_file(file) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("{err}");
                code = ExitCode::from(1);
                continue;
            }
        };
        let facts = match facts_of(file, &bytes) {
            Ok(facts) => facts,
            Err(err) => {
                eprintln!("{file}: {err}");
                code = ExitCode::from(1);
                continue;
            }
        };
        let misses = claim::judge(&facts, &claims);
        if !misses.is_empty() {
            code = ExitCode::from(1);
        }
        if !json && !first {
            println!("---");
        }
        first = false;
        print_report(&facts, &misses, json);
    }
    if count == 0 {
        return Err(format!("{path}: no file"));
    }
    Ok(code)
}

fn print_report(facts: &claim::Facts, misses: &[claim::Miss], json: bool) {
    if json {
        print!("{}", claim::report_json(facts, misses));
    } else {
        print!("{}", claim::report(facts, misses, color_stdout()));
    }
}

fn code_of(misses: &[claim::Miss]) -> ExitCode {
    if misses.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn args_of(args: impl Iterator<Item = String>) -> Result<Job, String> {
    let args: Vec<String> = args.collect();
    let mut json = false;
    let mut symbols = false;
    let mut check = false;
    let mut claims = None;
    let mut expect = Vec::new();
    let mut path = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--symbols" {
            symbols = true;
        } else if arg == "--check" {
            check = true;
        } else if arg == "--claims" {
            index += 1;
            let Some(file) = args.get(index) else {
                return Err(USAGE.into());
            };
            if file.starts_with('-') || claims.is_some() {
                return Err(USAGE.into());
            }
            claims = Some(file.clone());
        } else if arg == "--expect" {
            index += 1;
            let Some(token) = args.get(index) else {
                return Err(USAGE.into());
            };
            if token.starts_with('-') {
                return Err(USAGE.into());
            }
            expect.push(token.clone());
        } else if arg.starts_with('-') || path.is_some() {
            return Err(USAGE.into());
        } else {
            path = Some(arg.clone());
        }
        index += 1;
    }
    if let Some(file) = claims {
        if path.is_some() || check || !expect.is_empty() {
            return Err(USAGE.into());
        }
        return Ok(Job::Claims { path: file, json });
    }
    let Some(path) = path else {
        return Err(USAGE.into());
    };
    if check || !expect.is_empty() {
        return Ok(Job::Check { path, json, expect });
    }
    Ok(Job::Show {
        path,
        json,
        symbols,
    })
}

fn color_stdout() -> bool {
    io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none()
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| format!("cannot read {path}: {err}"))?;
    Ok(bytes)
}
