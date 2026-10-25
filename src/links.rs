/*
---
why: This file picks a link to open for the selected row.
uses: bininfo
how: The TUI passes the text of the selected row and its children.
The first rule that fits wins. A new link kind is a new rule.
---
*/

//! Links for the selected row. The `o` key opens one.

/// A place to read more about a row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub label: &'static str,
    pub url: String,
}

/// The link for a row, from its plain text and the text of its children.
pub fn for_block(block: &str) -> Option<Link> {
    advisory(block)
        .or_else(|| cert_search(block))
        .or_else(|| first_url(block))
}

// A cert row names its advisory in a `read:` line.
fn advisory(block: &str) -> Option<Link> {
    one_cert(block)?;
    let url = value_of(block, "read:")?;
    Some(Link {
        label: "advisory",
        url,
    })
}

// Every cert is findable by SHA-256 in public Certificate Transparency logs.
fn cert_search(block: &str) -> Option<Link> {
    let sha = one_cert(block)?;
    Some(Link {
        label: "crt.sh",
        url: format!("https://crt.sh/?sha256={sha}"),
    })
}

fn first_url(block: &str) -> Option<Link> {
    let start = block.find("https://").or_else(|| block.find("http://"))?;
    let url: String = block[start..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ')' && *c != ',')
        .collect();
    Some(Link { label: "link", url })
}

// The SHA-256 of a block that holds exactly one cert.
fn one_cert(block: &str) -> Option<String> {
    let mut found = block
        .lines()
        .filter_map(|line| value_of(line, "sha256:"))
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()));
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn value_of(block: &str, key: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix(key)?;
        let value = rest.split(" # ").next()?.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

/// Open a URL in the system browser.
pub fn open(url: &str) -> std::io::Result<()> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(std::io::Error::other("not a web link"));
    }
    let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "windows") {
        ("cmd", vec!["/c", "start", "", url])
    } else {
        ("xdg-open", vec![url])
    };
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b";

    #[test]
    fn a_cert_row_prefers_its_advisory() {
        let block = format!("- ✗ cn: a  # why\n  read: https://x.test/a\n  sha256: {SHA}\n");
        let link = for_block(&block).unwrap();
        assert_eq!(link.url, "https://x.test/a");
    }

    #[test]
    fn a_plain_cert_row_searches_by_hash() {
        let link = for_block(&format!("- ✓ cn: a\n  sha256: {SHA}\n")).unwrap();
        assert_eq!(link.url, format!("https://crt.sh/?sha256={SHA}"));
    }

    #[test]
    fn a_group_of_certs_has_no_cert_link() {
        let block = format!("certs:\n  sha256: {SHA}\n  sha256: {}\n", SHA.replace('8', "9"));
        assert_eq!(for_block(&block), None);
    }

    #[test]
    fn a_url_in_the_text_is_the_fallback() {
        let link = for_block("note: see https://a.test/x, ok").unwrap();
        assert_eq!(link.url, "https://a.test/x");
    }

    #[test]
    fn only_web_links_open() {
        assert!(open("file:///etc/passwd").is_err());
    }
}
