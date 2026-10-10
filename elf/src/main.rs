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
usage: elf-header [--json] [--check] [--expect <claim>] <file>
usage: elf-header [--json] --claims <file>";

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
    },
    Macho {
        image: macho::header::Image,
        commands: macho::load::Commands,
    },
    Pe {
        header: pe::header::Header,
        load: pe::load::Load,
    },
}

fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    match args_of(args)? {
        Job::Show { path, json } => {
            let bytes = read_file(&path)?;
            print!("{}", render(&path, &bytes, json)?);
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

fn render(path: &str, bytes: &[u8], json: bool) -> Result<String, String> {
    let color = color_stdout();
    match open(bytes)? {
        Opened::Elf { header, load } => Ok(if json {
            elf::json::render(path, &header, &load)
        } else {
            elf::page::render(path, &header, &load, color)
        }),
        Opened::Macho { image, commands } => Ok(if json {
            macho::json::render(path, &image, &commands)
        } else {
            macho::page::render(path, &image, &commands, color)
        }),
        Opened::Pe { header, load } => Ok(if json {
            pe::json::render(path, &header, &load)
        } else {
            pe::page::render(path, &header, &load, color)
        }),
    }
}

fn open(bytes: &[u8]) -> Result<Opened, String> {
    if elf::header::is_elf(bytes) {
        let header = elf::header::parse(bytes)?;
        let load = elf::load::read(bytes, &header);
        return Ok(Opened::Elf { header, load });
    }
    if macho::header::is_macho(bytes) {
        let image = macho::header::parse(bytes)?;
        let commands = macho::load::read(bytes, &image);
        return Ok(Opened::Macho { image, commands });
    }
    if pe::header::is_pe(bytes) {
        let header = pe::header::parse(bytes)?;
        let load = pe::load::read(bytes, &header);
        return Ok(Opened::Pe { header, load });
    }
    Err("not an ELF, Mach-O, or PE file".into())
}

fn facts_of(file: &str, bytes: &[u8]) -> Result<claim::Facts, String> {
    Ok(match open(bytes)? {
        Opened::Elf { load, .. } => claim::Facts {
            file: file.to_string(),
            format: "elf",
            kind: load.kind,
            interp: load.interp,
            needed: load.needed,
            pie: load.pie,
        },
        Opened::Macho { commands, .. } => claim::Facts {
            file: file.to_string(),
            format: "macho",
            kind: commands.load.kind,
            interp: commands.load.interp,
            needed: commands.load.needed,
            pie: commands.load.pie,
        },
        Opened::Pe { load, .. } => claim::Facts {
            file: file.to_string(),
            format: "pe",
            kind: load.kind,
            interp: load.interp,
            needed: load.needed,
            pie: load.pie,
        },
    })
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
    let mut check = false;
    let mut claims = None;
    let mut expect = Vec::new();
    let mut path = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
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
    Ok(Job::Show { path, json })
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
