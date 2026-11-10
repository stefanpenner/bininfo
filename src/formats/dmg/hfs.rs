/*
---
why: This file reads one HFS Plus catalog inside a disk part.
uses: bininfo
how: bininfo calls this file when enter opens one HFS part.
This file lists file names and reads one data fork.
This file does not read the next file.
A stopped watch ends the read.
---
*/

//! One HFS Plus catalog. The volume header starts at byte 1024.
//! This module lists files and reads one data fork.

use crate::style;
use std::fmt::Write;

const FILE_CAP: usize = 32;
const NODE_CAP: usize = 64;
const NODE_MAX: usize = 32768;

pub(super) enum Fault {
    Cap,
    Block(&'static str),
    Miss,
    Stop,
}

pub(super) struct File {
    pub name: String,
    pub size: u64,
    start: u32,
    blocks: u32,
}

pub(super) fn page(name: &str, files: &[File], more: bool, color: bool) -> String {
    let mut out = String::new();
    style::field(
        &mut out,
        color,
        0,
        "file",
        name,
        "Name of this part.",
        style::WHITE,
        false,
    );
    style::field(
        &mut out,
        color,
        0,
        "format",
        "hfs",
        "An HFS volume has no start claim.",
        style::FG,
        true,
    );
    style::blank(&mut out);
    style::rung(
        &mut out,
        color,
        "files",
        "Enter opens one file.",
        style::FG,
        true,
    );
    if more {
        style::field(
            &mut out,
            color,
            2,
            "more",
            "true",
            "The catalog walk stopped at the cap.",
            style::PINK,
            false,
        );
    }
    if files.is_empty() {
        style::field(
            &mut out,
            color,
            2,
            "rows",
            "[]",
            "No file in the kept rows.",
            style::LABEL,
            false,
        );
        return out;
    }
    for file in files {
        let shown = style::file_text(color, &file.name);
        let dash = style::paint(color, "-", style::LABEL, false);
        let _ = writeln!(out, "  {dash} {shown}");
        style::field(
            &mut out,
            color,
            4,
            "size",
            &file.size.to_string(),
            "Data fork byte length.",
            style::FG,
            false,
        );
    }
    out
}

pub(super) fn list(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, Fault>,
) -> Result<(Vec<File>, bool), Fault> {
    walk(read)
}

pub(super) fn file_bytes(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, Fault>,
    name: &str,
) -> Result<Vec<u8>, Fault> {
    let (files, _) = walk(read)?;
    let file = files
        .iter()
        .find(|file| file.name == name)
        .ok_or(Fault::Miss)?;
    if file.size == 0 || file.blocks == 0 {
        return Err(Fault::Miss);
    }
    let header = read(1024, 512)?;
    let block = block_size(&header)?;
    let at = u64::from(file.start)
        .checked_mul(u64::from(block))
        .ok_or(Fault::Miss)?;
    let len = usize::try_from(file.size).map_err(|_| Fault::Cap)?;
    let bytes = read(at, len)?;
    if bytes.len() < len {
        return Err(Fault::Miss);
    }
    Ok(bytes)
}

fn walk(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, Fault>,
) -> Result<(Vec<File>, bool), Fault> {
    let header = read(1024, 512)?;
    let block = block_size(&header)?;
    let start = u32_be(&header, 288).ok_or(Fault::Miss)?;
    let base = u64::from(start)
        .checked_mul(u64::from(block))
        .ok_or(Fault::Miss)?;
    let head = read(base, 512)?;
    if head.get(8) != Some(&1) {
        return Err(Fault::Miss);
    }
    let node_size = u32::from(u16_be(&head, 32).ok_or(Fault::Miss)?);
    if !(512..=NODE_MAX).contains(&(node_size as usize)) {
        return Err(Fault::Miss);
    }
    let mut node = u64::from(u32_be(&head, 24).ok_or(Fault::Miss)?);
    let mut files = Vec::new();
    let mut more = false;
    let mut seen = 0usize;
    let mut prev = None;
    while node != 0 && seen < NODE_CAP && files.len() < FILE_CAP {
        if prev == Some(node) {
            break;
        }
        seen += 1;
        let at = base
            .checked_add(node.checked_mul(u64::from(node_size)).ok_or(Fault::Miss)?)
            .ok_or(Fault::Miss)?;
        let bytes = read(at, node_size as usize)?;
        let next = u64::from(u32_be(&bytes, 0).ok_or(Fault::Miss)?);
        if bytes.get(8) == Some(&0xff) {
            more |= read_leaf(&bytes, &mut files);
        }
        prev = Some(node);
        node = next;
    }
    if seen == NODE_CAP || files.len() == FILE_CAP {
        more = true;
    }
    Ok((files, more))
}

fn read_leaf(node: &[u8], files: &mut Vec<File>) -> bool {
    let Some(count) = u16_be(node, 10) else {
        return true;
    };
    let mut bad = false;
    for index in 0..count {
        if files.len() == FILE_CAP {
            return true;
        }
        let slot = 2 * (usize::from(index) + 1);
        if slot > node.len() {
            return true;
        }
        let Some(off) = u16_be(node, node.len() - slot) else {
            return true;
        };
        let off = usize::from(off);
        if off >= node.len() {
            bad = true;
            continue;
        }
        match one_record(&node[off..]) {
            Some(Some(file)) => files.push(file),
            Some(None) => {}
            None => bad = true,
        }
    }
    bad
}

/// `Some(None)` is a record this reader skips.
/// `None` is a truncated record.
fn one_record(rec: &[u8]) -> Option<Option<File>> {
    let key_len = usize::from(u16_be(rec, 0)?);
    if key_len < 6 || rec.len() < 2 + key_len {
        return None;
    }
    let name_len = usize::from(u16_be(rec, 6)?);
    if 8 + name_len * 2 > 2 + key_len {
        return None;
    }
    let body = 2 + key_len;
    let kind = u16_be(rec, body)?;
    if kind != 2 {
        return Some(None);
    }
    if name_len == 0 || rec.len() < body + 112 {
        return None;
    }
    let mut units = Vec::with_capacity(name_len);
    for index in 0..name_len {
        units.push(u16_be(rec, 8 + index * 2)?);
    }
    let name = String::from_utf16(&units).ok()?;
    if name.len() > 255 {
        return None;
    }
    let size = u64_be(rec, body + 88)?;
    let start = u32_be(rec, body + 104)?;
    let blocks = u32_be(rec, body + 108)?;
    Some(Some(File {
        name,
        size,
        start,
        blocks,
    }))
}

fn block_size(header: &[u8]) -> Result<u32, Fault> {
    let sig = u16_be(header, 0).ok_or(Fault::Miss)?;
    if sig != 0x482b && sig != 0x4858 {
        return Err(Fault::Miss);
    }
    let version = u16_be(header, 2).ok_or(Fault::Miss)?;
    if version != 4 && version != 5 {
        return Err(Fault::Miss);
    }
    let block = u32_be(header, 40).ok_or(Fault::Miss)?;
    if block < 512 || block > 1 << 20 || block % 512 != 0 {
        return Err(Fault::Miss);
    }
    Ok(block)
}

fn u16_be(bytes: &[u8], at: usize) -> Option<u16> {
    let s = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    let s = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_be(bytes: &[u8], at: usize) -> Option<u64> {
    let s = bytes.get(at..at + 8)?;
    Some(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}
