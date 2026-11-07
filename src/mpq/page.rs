/*
---
why: This file writes one MPQ archive as one text page.
uses: bininfo
how: bininfo calls this file after it reads an MPQ archive.
This file does not read MPQ bytes.
---
*/

//! One page for one MPQ archive.
//! Each line is `key: value  # note`. This file does not read MPQ bytes.

use super::{flag_names, Archive, Block};
use crate::style::{self, Json};
use std::fmt::Write;

pub fn render(file: &str, archive: &Archive, color: bool) -> String {
    let mut out = String::new();
    style::field(
        &mut out,
        color,
        0,
        "file",
        file,
        "Path of this file.",
        style::WHITE,
        false,
    );
    style::field(
        &mut out,
        color,
        0,
        "format",
        "mpq",
        "An MPQ archive has no start claim.",
        style::FG,
        true,
    );
    style::blank(&mut out);
    type_rung(&mut out, archive, color);
    style::blank(&mut out);
    tables_rung(&mut out, archive, color);
    style::blank(&mut out);
    blocks_rung(&mut out, archive, color);
    out
}

pub fn render_json(file: &str, archive: &Archive) -> String {
    let mut out = Json::new();
    out.str("file", file);
    out.str("format", "mpq");
    out.str("magic", "MPQ");
    out.u64("version", u64::from(archive.version));
    out.u64("header", u64::from(archive.header_size));
    out.u64("sector", archive.sector);
    out.u64("archive", archive.archive_size);
    out.u64("hash_offset", archive.hash_offset);
    out.u64("hash_count", u64::from(archive.hash_count));
    out.u64("block_offset", archive.block_offset);
    out.u64("block_count", u64::from(archive.block_count));
    out.u64("files", archive.files);
    out.u64("compressed", archive.compressed);
    out.u64("encrypted", archive.encrypted);
    let rows: Vec<String> = archive.blocks.iter().map(block_json).collect();
    out.raw_array("blocks", &rows);
    out.u64("more", archive.more);
    out.finish()
}

fn type_rung(out: &mut String, archive: &Archive, color: bool) {
    style::rung(
        out,
        color,
        "type",
        "Magic, version, header size, and sector size.",
        style::GREEN,
        true,
    );
    style::field(
        out,
        color,
        2,
        "magic",
        "MPQ",
        "Archive magic.",
        style::FG,
        false,
    );
    num(
        out,
        color,
        "version",
        u64::from(archive.version),
        "Header version.",
    );
    num(
        out,
        color,
        "header",
        u64::from(archive.header_size),
        "Byte length of the header.",
    );
    num(
        out,
        color,
        "sector",
        archive.sector,
        "Sector size in bytes.",
    );
    if archive.version >= 2 {
        style::field(
            out,
            color,
            2,
            "wide",
            "unread",
            "A file offset above 4 GiB stays unread.",
            style::FG,
            false,
        );
    }
}

fn tables_rung(out: &mut String, archive: &Archive, color: bool) {
    style::rung(
        out,
        color,
        "tables",
        "Table positions and block counts.",
        style::FG,
        true,
    );
    num(
        out,
        color,
        "archive",
        archive.archive_size,
        "Byte length of the archive.",
    );
    num(
        out,
        color,
        "hash_offset",
        archive.hash_offset,
        "Byte offset of the hash table.",
    );
    num(
        out,
        color,
        "hash_count",
        u64::from(archive.hash_count),
        "Entries in the hash table.",
    );
    num(
        out,
        color,
        "block_offset",
        archive.block_offset,
        "Byte offset of the block table.",
    );
    num(
        out,
        color,
        "block_count",
        u64::from(archive.block_count),
        "Entries in the block table.",
    );
    num(
        out,
        color,
        "files",
        archive.files,
        "Blocks with the exists flag.",
    );
    num(
        out,
        color,
        "compressed",
        archive.compressed,
        "Blocks with a compression flag.",
    );
    num(
        out,
        color,
        "encrypted",
        archive.encrypted,
        "Blocks with the encrypted flag.",
    );
}

fn blocks_rung(out: &mut String, archive: &Archive, color: bool) {
    style::rung(
        out,
        color,
        "blocks",
        "The row name is the file offset. A listfile name is not read.",
        style::FG,
        true,
    );
    if archive.blocks.is_empty() {
        style::field(
            out,
            color,
            2,
            "rows",
            "[]",
            "No block in the kept rows.",
            style::LABEL,
            false,
        );
        return;
    }
    for block in &archive.blocks {
        write_block(out, block, color);
    }
    style::more_row(out, 2, archive.more as usize);
}

fn write_block(out: &mut String, block: &Block, color: bool) {
    let dash = style::paint(color, "-", style::LABEL, false);
    let _ = writeln!(out, "  {dash} {}", block.offset);
    num_at(out, color, 4, "stored", block.stored, "Stored size.");
    num_at(out, color, 4, "size", block.size, "Uncompressed size.");
    style::field(
        out,
        color,
        4,
        "flags",
        &flag_words(block.flags),
        "Block flags.",
        style::FG,
        false,
    );
}

fn num(out: &mut String, color: bool, key: &str, value: u64, note: &str) {
    num_at(out, color, 2, key, value, note);
}

fn num_at(out: &mut String, color: bool, indent: usize, key: &str, value: u64, note: &str) {
    let (fg, bold) = style::number_tone(value, style::FG, false);
    style::field(out, color, indent, key, &value.to_string(), note, fg, bold);
}

fn flag_words(flags: u32) -> String {
    let (names, rest) = flag_names(flags);
    if names.is_empty() && rest == 0 {
        return "none".to_string();
    }
    let mut text = names.join(", ");
    if rest != 0 {
        if !text.is_empty() {
            text.push_str(", ");
        }
        let _ = write!(text, "0x{rest:X}");
    }
    text
}

fn flag_list(flags: u32) -> Vec<String> {
    let (names, rest) = flag_names(flags);
    let mut out: Vec<String> = names.into_iter().map(str::to_string).collect();
    if rest != 0 {
        out.push(format!("0x{rest:X}"));
    }
    out
}

fn block_json(block: &Block) -> String {
    let mut out = Json::new();
    out.u64("offset", block.offset);
    out.u64("stored", block.stored);
    out.u64("size", block.size);
    out.strings("flags", &flag_list(block.flags));
    out.finish_inline()
}
