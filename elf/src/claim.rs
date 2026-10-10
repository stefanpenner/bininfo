//! The claim a header makes about how a file starts.
//! A hermetic header names no other file.
//! This file does not read ELF, Mach-O, or PE bytes.

use crate::kind::{self, Kind};
use crate::style::{self, Json};
use std::fmt::Write;

/// Load facts for one file. The check reads this. It does not read the bytes again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub file: String,
    pub format: &'static str,
    pub kind: Kind,
    pub interp: Option<String>,
    pub needed: Vec<String>,
    pub pie: bool,
}

/// One fact the caller asked the file to match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    Hermetic(bool),
    Kind(Kind),
    Pie(bool),
    Interp(Option<String>),
    Needed(Vec<String>),
}

/// A claim that did not match the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Miss {
    pub claim: String,
    pub found: String,
}

pub fn is_hermetic(kind: Kind, interp: Option<&str>, needed: &[String]) -> bool {
    matches!(kind, Kind::Static | Kind::StaticPie) && interp.is_none() && needed.is_empty()
}

pub fn sentence(kind: Kind, interp: Option<&str>, needed: &[String]) -> &'static str {
    if matches!(kind, Kind::Rel) {
        return "This file is an object. It does not start a run.";
    }
    if matches!(kind, Kind::Shared) {
        return "This file is a library. It does not start a run.";
    }
    if matches!(kind, Kind::Other) {
        return "This file is outside the four start kinds.";
    }
    if is_hermetic(kind, interp, needed) {
        return "This program starts itself and names no other file.";
    }
    "This program names a loader or a library."
}

pub fn hermetic_note(kind: Kind, yes: bool) -> &'static str {
    if yes {
        return "The header closure is this file. This check does not read dlopen.";
    }
    match kind {
        Kind::Shared => "A library does not start a run.",
        Kind::Rel => "An object file does not start a run.",
        Kind::Other => "This file is outside the four start kinds.",
        _ => "The header names another file. This check does not read dlopen.",
    }
}

pub fn write_tail(
    out: &mut String,
    color: bool,
    kind: Kind,
    interp: Option<&str>,
    needed: &[String],
) {
    let yes = is_hermetic(kind, interp, needed);
    let (fg, bold) = if yes {
        (style::GREEN, true)
    } else {
        (style::PINK, true)
    };
    style::field(
        out,
        color,
        2,
        "hermetic",
        if yes { "true" } else { "false" },
        hermetic_note(kind, yes),
        fg,
        bold,
    );
    style::field(
        out,
        color,
        2,
        "says",
        sentence(kind, interp, needed),
        "One sentence for these load facts.",
        style::FG,
        false,
    );
}

pub fn write_load(out: &mut Json, kind: Kind, interp: Option<&str>, needed: &[String], pie: bool) {
    out.load(
        kind::name(kind),
        interp,
        needed,
        pie,
        is_hermetic(kind, interp, needed),
        sentence(kind, interp, needed),
    );
}

pub fn parse(tokens: &[String]) -> Result<Vec<Claim>, String> {
    let mut claims = Vec::new();
    let mut needed: Option<Vec<String>> = None;
    let mut saw_hermetic = false;
    let mut saw_kind = false;
    let mut saw_pie = false;
    let mut saw_interp = false;
    for token in tokens {
        if let Some(name) = token.strip_prefix("needed=") {
            let list = needed.get_or_insert_with(Vec::new);
            if !name.is_empty() {
                list.push(name.to_string());
            }
            continue;
        }
        if token == "hermetic" || token == "hermetic=true" {
            if saw_hermetic {
                return Err("duplicate claim: hermetic".into());
            }
            saw_hermetic = true;
            claims.push(Claim::Hermetic(true));
            continue;
        }
        if let Some(value) = token.strip_prefix("hermetic=") {
            if saw_hermetic {
                return Err("duplicate claim: hermetic".into());
            }
            saw_hermetic = true;
            claims.push(Claim::Hermetic(parse_bool(value)?));
            continue;
        }
        if let Some(value) = token.strip_prefix("kind=") {
            if saw_kind {
                return Err("duplicate claim: kind".into());
            }
            saw_kind = true;
            claims.push(Claim::Kind(parse_kind(value)?));
            continue;
        }
        if let Some(value) = token.strip_prefix("pie=") {
            if saw_pie {
                return Err("duplicate claim: pie".into());
            }
            saw_pie = true;
            claims.push(Claim::Pie(parse_bool(value)?));
            continue;
        }
        if let Some(value) = token.strip_prefix("interp=") {
            if saw_interp {
                return Err("duplicate claim: interp".into());
            }
            saw_interp = true;
            let path = if value == "null" {
                None
            } else {
                Some(value.to_string())
            };
            claims.push(Claim::Interp(path));
            continue;
        }
        return Err(format!("unknown claim: {token}"));
    }
    if let Some(list) = needed {
        claims.push(Claim::Needed(list));
    }
    Ok(claims)
}

pub fn judge(facts: &Facts, claims: &[Claim]) -> Vec<Miss> {
    let mut misses = Vec::new();
    for claim in claims {
        match claim {
            Claim::Hermetic(want) => {
                let got = is_hermetic(facts.kind, facts.interp.as_deref(), &facts.needed);
                if got != *want {
                    misses.push(Miss {
                        claim: format!("hermetic={want}"),
                        found: bool_word(got).into(),
                    });
                }
            }
            Claim::Kind(want) => {
                if facts.kind != *want {
                    misses.push(Miss {
                        claim: format!("kind={}", kind::name(*want)),
                        found: kind::name(facts.kind).into(),
                    });
                }
            }
            Claim::Pie(want) => {
                if facts.pie != *want {
                    misses.push(Miss {
                        claim: format!("pie={want}"),
                        found: bool_word(facts.pie).into(),
                    });
                }
            }
            Claim::Interp(want) => {
                if facts.interp.as_deref() != want.as_deref() {
                    misses.push(Miss {
                        claim: format!("interp={}", want.as_deref().unwrap_or("null")),
                        found: facts.interp.clone().unwrap_or_else(|| "null".into()),
                    });
                }
            }
            Claim::Needed(want) => {
                if &facts.needed != want {
                    misses.push(Miss {
                        claim: format!("needed={}", needed_token(want)),
                        found: style::yaml_list(&facts.needed),
                    });
                }
            }
        }
    }
    misses
}

pub fn report(facts: &Facts, misses: &[Miss], color: bool) -> String {
    let yes = is_hermetic(facts.kind, facts.interp.as_deref(), &facts.needed);
    let mut out = String::new();
    style::field(
        &mut out,
        color,
        0,
        "file",
        &facts.file,
        "Path of this file.",
        style::WHITE,
        false,
    );
    style::field(
        &mut out,
        color,
        0,
        "format",
        facts.format,
        "elf, macho, or pe.",
        style::FG,
        true,
    );
    let (fg, bold) = style::kind_tone(facts.kind);
    style::field(
        &mut out,
        color,
        0,
        "kind",
        kind::name(facts.kind),
        "Start kind. The same word in each format.",
        fg,
        bold,
    );
    style::field(
        &mut out,
        color,
        0,
        "pie",
        bool_word(facts.pie),
        "Position-independent bit.",
        if facts.pie {
            style::GREEN
        } else {
            style::LABEL
        },
        facts.pie,
    );
    let interp = facts.interp.as_deref().unwrap_or("null");
    style::field(
        &mut out,
        color,
        0,
        "interp",
        interp,
        "Path of the loader. null means this file starts itself.",
        if facts.interp.is_some() {
            style::WHITE
        } else {
            style::LABEL
        },
        false,
    );
    style::raw_field(
        &mut out,
        color,
        0,
        "needed",
        &style::yaml_list(&facts.needed),
        "Library names the loader opens.",
        if facts.needed.is_empty() {
            style::LABEL
        } else {
            style::WHITE
        },
        false,
    );
    let (fg, bold) = if yes {
        (style::GREEN, true)
    } else {
        (style::PINK, true)
    };
    style::field(
        &mut out,
        color,
        0,
        "hermetic",
        bool_word(yes),
        hermetic_note(facts.kind, yes),
        fg,
        bold,
    );
    style::field(
        &mut out,
        color,
        0,
        "says",
        sentence(facts.kind, facts.interp.as_deref(), &facts.needed),
        "One sentence for these load facts.",
        style::FG,
        false,
    );
    let pass = misses.is_empty();
    style::field(
        &mut out,
        color,
        0,
        "result",
        if pass { "pass" } else { "fail" },
        "pass means every claim matched.",
        if pass { style::GREEN } else { style::PINK },
        true,
    );
    if !misses.is_empty() {
        style::blank(&mut out);
        style::rung(
            &mut out,
            color,
            "miss",
            "A claim that did not match.",
            style::PINK,
            true,
        );
        for miss in misses {
            let _ = writeln!(out, "  - claim: {}", miss.claim);
            let _ = writeln!(out, "    found: {}", miss.found);
        }
    }
    out
}

pub fn report_json(facts: &Facts, misses: &[Miss]) -> String {
    let yes = is_hermetic(facts.kind, facts.interp.as_deref(), &facts.needed);
    let mut out = Json::new();
    out.str("file", &facts.file);
    out.str("format", facts.format);
    out.str("kind", kind::name(facts.kind));
    out.flag("pie", facts.pie);
    out.opt("interp", facts.interp.as_deref());
    out.strings("needed", &facts.needed);
    out.flag("hermetic", yes);
    out.str(
        "says",
        sentence(facts.kind, facts.interp.as_deref(), &facts.needed),
    );
    out.str("result", if misses.is_empty() { "pass" } else { "fail" });
    let rows: Vec<(&str, &str)> = misses
        .iter()
        .map(|miss| (miss.claim.as_str(), miss.found.as_str()))
        .collect();
    out.pairs("miss", "claim", "found", &rows);
    out.finish()
}

fn parse_kind(token: &str) -> Result<Kind, String> {
    match token {
        "static" => Ok(Kind::Static),
        "dynamic" => Ok(Kind::Dynamic),
        "dynamic-pie" => Ok(Kind::DynamicPie),
        "static-pie" => Ok(Kind::StaticPie),
        "shared" => Ok(Kind::Shared),
        "rel" => Ok(Kind::Rel),
        "other" => Ok(Kind::Other),
        _ => Err(format!("unknown kind: {token}")),
    }
}

fn parse_bool(token: &str) -> Result<bool, String> {
    match token {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("unknown value: {token}")),
    }
}

fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn needed_token(names: &[String]) -> String {
    if names.is_empty() {
        "[]".to_string()
    } else {
        names.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(kind: Kind, interp: Option<&str>, needed: &[&str], pie: bool) -> Facts {
        Facts {
            file: "bin".into(),
            format: "elf",
            kind,
            interp: interp.map(str::to_string),
            needed: needed.iter().map(|name| (*name).to_string()).collect(),
            pie,
        }
    }

    #[test]
    fn a_closed_program_is_hermetic() {
        assert!(is_hermetic(Kind::Static, None, &[]));
        assert!(is_hermetic(Kind::StaticPie, None, &[]));
        assert!(!is_hermetic(Kind::Static, None, &["libtiny.so".into()]));
        assert!(!is_hermetic(Kind::Static, Some("/lib/ld.so"), &[]));
        assert!(!is_hermetic(Kind::Dynamic, Some("/lib/ld.so"), &[]));
        assert!(!is_hermetic(Kind::DynamicPie, None, &["a.dll".into()]));
        assert!(!is_hermetic(Kind::Shared, None, &[]));
        assert!(!is_hermetic(Kind::Rel, None, &[]));
        assert!(!is_hermetic(Kind::Other, None, &[]));
    }

    #[test]
    fn the_sentence_follows_the_kind() {
        assert_eq!(
            sentence(Kind::StaticPie, None, &[]),
            "This program starts itself and names no other file."
        );
        assert_eq!(
            sentence(
                Kind::Shared,
                Some("/usr/lib/dyld"),
                &["/usr/lib/libSystem.B.dylib".into()]
            ),
            "This file is a library. It does not start a run."
        );
        assert_eq!(
            sentence(Kind::Rel, None, &[]),
            "This file is an object. It does not start a run."
        );
        assert_eq!(
            sentence(Kind::DynamicPie, Some("/lib/ld.so"), &["libtiny.so".into()]),
            "This program names a loader or a library."
        );
    }

    #[test]
    fn claims_match_or_name_the_miss() {
        let closed = facts(Kind::Static, None, &[], false);
        let claims = parse(&[
            "hermetic".into(),
            "kind=static".into(),
            "pie=false".into(),
            "interp=null".into(),
            "needed=".into(),
        ])
        .unwrap();
        assert!(judge(&closed, &claims).is_empty());

        let open = facts(Kind::DynamicPie, Some("/lib/ld.so"), &["libtiny.so"], true);
        let misses = judge(
            &open,
            &parse(&["hermetic".into(), "needed=other.so".into()]).unwrap(),
        );
        assert_eq!(misses[0].claim, "hermetic=true");
        assert_eq!(misses[0].found, "false");
        assert_eq!(misses[1].claim, "needed=other.so");
        assert_eq!(misses[1].found, "[libtiny.so]");
    }

    #[test]
    fn needed_order_is_exact_and_bad_tokens_fail() {
        let file = facts(
            Kind::DynamicPie,
            Some("/usr/lib/dyld"),
            &["libtiny.dylib", "/usr/lib/libSystem.B.dylib"],
            true,
        );
        let claims = parse(&[
            "needed=libtiny.dylib".into(),
            "needed=/usr/lib/libSystem.B.dylib".into(),
        ])
        .unwrap();
        assert!(judge(&file, &claims).is_empty());
        let swapped = parse(&[
            "needed=/usr/lib/libSystem.B.dylib".into(),
            "needed=libtiny.dylib".into(),
        ])
        .unwrap();
        assert_eq!(judge(&file, &swapped).len(), 1);

        assert!(parse(&["kind=static".into(), "kind=rel".into()]).is_err());
        assert!(parse(&["pie=yes".into()]).is_err());
        assert!(parse(&["nope".into()]).is_err());
    }

    #[test]
    fn the_report_shows_pass_and_fail() {
        let closed = facts(Kind::Static, None, &[], false);
        let pass = report(&closed, &[], false);
        assert!(pass.contains("hermetic: true"), "{pass}");
        assert!(pass.contains("result: pass"), "{pass}");
        assert!(
            pass.contains("This program starts itself and names no other file."),
            "{pass}"
        );
        assert!(!pass.contains("\nmiss:"), "{pass}");

        let misses = judge(&closed, &parse(&["kind=shared".into()]).unwrap());
        let fail = report(&closed, &misses, false);
        assert!(fail.contains("result: fail"), "{fail}");
        assert!(fail.contains("claim: kind=shared"), "{fail}");
        assert!(fail.contains("found: static"), "{fail}");

        let json = report_json(&closed, &misses);
        assert!(json.contains(r#""result":"fail""#), "{json}");
        assert!(json.contains(r#""hermetic":true"#), "{json}");
        assert!(json.contains(r#""claim":"kind=shared""#), "{json}");
        assert!(json.contains(r#""found":"static""#), "{json}");
    }
}
