/*
---
why: This file is the bininfo command.
uses: bininfo
how: The command reads arguments and one file.
A terminal folds the page.
A pipe prints the full page.
It calls the bininfo library to print a page or check a claim.
---
*/

//! Read an ELF, Mach-O, or PE header and print it.
//! A terminal folds the page. A pipe prints the full page.
//! `--check` asks whether the header names no other file.

mod fold;
mod tui;

use std::env;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;

use bininfo::summary::{hex, hit_json, json_str};

const USAGE: &str = "\
usage: bininfo [--json] [--symbols] [--check] [--expect <claim>] <file>
usage: bininfo --certs [--json] [--match <pem>]... [--match-cn <name>]... <file>
usage: bininfo --features
usage: bininfo [--json] --claims <file>
A terminal folds the page. A pipe prints the full page.";

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
    Certs {
        path: String,
        json: bool,
        want: Want,
    },
    Features,
}

/// What `--certs` keeps. Empty keeps every hit.
#[derive(Default)]
struct Want {
    /// SHA-256 of a cert or of a public key, as lowercase hex.
    hashes: Vec<String>,
    /// Subject common names.
    names: Vec<String>,
    /// True when the caller asked to match, even with nothing to match.
    on: bool,
}

fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    match args_of(args)? {
        Job::Show {
            path,
            json,
            symbols,
        } => {
            let bytes = read_file(&path)?;
            let file = bininfo::open(&bytes, symbols)?;
            let color = color_stdout();
            let page = bininfo::render(&path, &file, json, color);
            let summary = bininfo::summary::read(&bytes);
            let text = bininfo::summary::merge(&page, &summary, json, color);
            if fold::interactive(io::stdout().is_terminal(), json) {
                tui::run(&text).map_err(|err| err.to_string())?;
            } else {
                print!("{text}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Job::Check { path, json, expect } => {
            let tokens = if expect.is_empty() {
                vec!["hermetic".to_string()]
            } else {
                expect
            };
            let claims = bininfo::claim::parse(&tokens)?;
            check_one(&path, &claims, json)
        }
        Job::Claims { path, json } => check_file(&path, json),
        Job::Features => {
            println!("certs\nmatch\npage-certs\nschema 1");
            Ok(ExitCode::SUCCESS)
        }
        Job::Certs { path, json, want } => {
            let bytes = read_file(&path)?;
            let (page, hits) = certs_page(&path, &bytes, json, &want);
            print!("{page}");
            Ok(if want.on && hits > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}

/// Why a hit matched: the cert hash, the key hash, or the name.
fn matched_by(hit: &bininfo::certs::Hit, want: &Want) -> Option<&'static str> {
    let sha = hex(&hit.sha256);
    let spki = hex(&hit.spki_sha256);
    if want.hashes.contains(&sha) {
        Some("sha256")
    } else if want.hashes.contains(&spki) {
        Some("spki")
    } else if hit
        .subject_cn
        .as_ref()
        .is_some_and(|cn| want.names.contains(cn))
    {
        Some("cn")
    } else {
        None
    }
}

/// The page and the number of hits it lists. With a match request, signer
/// certificates never match and only matches are listed.
/// `--json` prints one object: `{"version":1,"file":...,"certs":[...]}`.
/// Text prints one tab-separated line per hit.
fn certs_page(path: &str, bytes: &[u8], json: bool, want: &Want) -> (String, usize) {
    let mut rows = Vec::new();
    for hit in bininfo::certs(bytes) {
        let by = if want.on {
            if hit.role == bininfo::certs::Role::Signer {
                continue;
            }
            match matched_by(&hit, want) {
                Some(by) => Some(by),
                None => continue,
            }
        } else {
            None
        };
        let kind = format!("{:?}", hit.kind).to_lowercase();
        let role = format!("{:?}", hit.role).to_lowercase();
        let container = format!("{:?}", hit.container).to_lowercase();
        let sha = hex(&hit.sha256);
        let spki = hex(&hit.spki_sha256);
        let cn = hit.subject_cn.as_deref();
        if json {
            rows.push(hit_json(&hit, by));
        } else {
            rows.push(format!(
                "{kind}\t{role}\t{container}\t{}\t{sha}\t{spki}\t{}\t{}",
                hit.place,
                cn.unwrap_or(""),
                by.unwrap_or(""),
            ));
        }
    }
    let count = rows.len();
    let page = if json {
        format!(
            "{{\"version\":1,\"file\":{},\"certs\":[{}]}}\n",
            json_str(path),
            rows.join(",")
        )
    } else {
        rows.iter().map(|r| format!("{r}\n")).collect()
    };
    (page, count)
}

fn check_one(path: &str, claims: &[bininfo::claim::Claim], json: bool) -> Result<ExitCode, String> {
    let bytes = read_file(path)?;
    let file = bininfo::open(&bytes, false)?;
    let facts = bininfo::facts(path, &file, &bininfo::current_host());
    let misses = bininfo::claim::judge(&facts, claims);
    print_report(&facts, &misses, json);
    Ok(code_of(&misses))
}

fn check_file(path: &str, json: bool) -> Result<ExitCode, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let mut code = ExitCode::SUCCESS;
    let mut count = 0usize;
    let mut first = true;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.chars().all(|c| c == '\u{200b}' || c == '\u{feff}')
        {
            continue;
        }
        count += 1;
        let mut parts = line.split_whitespace();
        let file = parts.next().expect("a trimmed line has a token");
        let tokens: Vec<String> = parts.map(str::to_string).collect();
        let claims =
            bininfo::claim::parse(&tokens).map_err(|err| format!("{path}:{}: {err}", index + 1))?;
        let claims = if claims.is_empty() {
            bininfo::claim::parse(&["hermetic".to_string()])?
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
        let opened = match bininfo::open(&bytes, false) {
            Ok(opened) => opened,
            Err(err) => {
                eprintln!("{file}: {err}");
                code = ExitCode::from(1);
                continue;
            }
        };
        let facts = bininfo::facts(file, &opened, &bininfo::current_host());
        let misses = bininfo::claim::judge(&facts, &claims);
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

fn print_report(facts: &bininfo::claim::Facts, misses: &[bininfo::claim::Miss], json: bool) {
    if json {
        print!("{}", bininfo::claim::report_json(facts, misses));
    } else {
        print!("{}", bininfo::claim::report(facts, misses, color_stdout()));
    }
}

fn code_of(misses: &[bininfo::claim::Miss]) -> ExitCode {
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
    let mut certs = false;
    let mut features = false;
    let mut want = Want::default();
    let mut claims = None;
    let mut expect = Vec::new();
    let mut path = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if path.is_some() || claims.is_some() {
            return Err(USAGE.into());
        }
        if arg == "--json" {
            json = true;
        } else if arg == "--symbols" {
            symbols = true;
        } else if arg == "--certs" {
            certs = true;
        } else if arg == "--features" {
            features = true;
        } else if arg == "--match" || arg == "--match-cn" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(USAGE.into());
            };
            want.on = true;
            if arg == "--match" {
                let pem = read_file(value)?;
                for hit in bininfo::certs(&pem) {
                    want.hashes.push(hex(&hit.sha256));
                    want.hashes.push(hex(&hit.spki_sha256));
                }
            } else {
                want.names.push(value.clone());
            }
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
        if path.is_some() || check || certs || symbols || !expect.is_empty() {
            return Err(USAGE.into());
        }
        return Ok(Job::Claims { path: file, json });
    }
    if features {
        if path.is_some() || certs || check || symbols || json || want.on || !expect.is_empty() {
            return Err(USAGE.into());
        }
        return Ok(Job::Features);
    }
    let Some(path) = path else {
        return Err(USAGE.into());
    };
    if want.on && !certs {
        return Err(USAGE.into());
    }
    if certs {
        if check || symbols || !expect.is_empty() {
            return Err(USAGE.into());
        }
        return Ok(Job::Certs { path, json, want });
    }
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
