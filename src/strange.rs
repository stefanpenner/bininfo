/*
---
why: This file holds one slot for each strange format.
uses: bininfo
how: bininfo calls this file after ELF, Mach-O, and PE.
The next format adds one module and one slot.
---
*/

//! A strange format is one sniff function and one parse function.
//! ELF, Mach-O, and PE are not in this list.
//! The next format adds one module and one slot in this file.

use crate::mpq;

/// One parsed file that has no start claim.
pub struct Opened {
    inner: Box<dyn File>,
}

impl Opened {
    pub fn page(&self, path: &str, color: bool) -> String {
        self.inner.page(path, color)
    }

    pub fn json(&self, path: &str) -> String {
        self.inner.json(path)
    }
}

trait File {
    fn page(&self, path: &str, color: bool) -> String;
    fn json(&self, path: &str) -> String;
}

impl File for mpq::Archive {
    fn page(&self, path: &str, color: bool) -> String {
        mpq::page::render(path, self, color)
    }

    fn json(&self, path: &str) -> String {
        mpq::page::render_json(path, self)
    }
}

struct Slot {
    sniff: fn(&[u8]) -> bool,
    parse: fn(&[u8]) -> Result<Opened, String>,
}

const SLOTS: &[Slot] = &[Slot {
    sniff: mpq::is_mpq,
    parse: open_mpq,
}];

pub fn open(bytes: &[u8]) -> Option<Result<Opened, String>> {
    SLOTS
        .iter()
        .find(|slot| (slot.sniff)(bytes))
        .map(|slot| (slot.parse)(bytes))
}

fn open_mpq(bytes: &[u8]) -> Result<Opened, String> {
    Ok(Opened {
        inner: Box::new(mpq::parse(bytes)?),
    })
}
