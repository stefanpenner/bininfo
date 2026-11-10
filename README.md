<!--
---
why: This file tells a reader what bininfo prints and how to run it.
uses: a reader
how: The reader opens this file in the repo.
The type list links each type to its reader.
The file also states how enter opens one file inside another.
---
-->

# bininfo

## What is this?

`bininfo` reads one file and prints one page.
A start page has type, load, symbols, sizes, where, and sections.
The load rung also shows soname, filter, auxiliary, and flags.
The sign rung says whether a Mach-O or PE signature is valid.

## File types

The format word is the type name.
The link opens the reader for that type.
Several raw words share one TIFF reader.
Several media words share one ISOBMFF reader.
The sniff list is [`src/formats/mod.rs`](src/formats/mod.rs).

| type | reader |
| --- | --- |
| `7z` | [`src/formats/sevenz/mod.rs`](src/formats/sevenz/mod.rs) |
| `ar` | [`src/formats/ar/mod.rs`](src/formats/ar/mod.rs) |
| `arw` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `avif` | [`src/formats/isobmff/mod.rs`](src/formats/isobmff/mod.rs) |
| `cpio` | [`src/formats/cpio/mod.rs`](src/formats/cpio/mod.rs) |
| `cr2` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `cr3` | [`src/formats/isobmff/mod.rs`](src/formats/isobmff/mod.rs) |
| `dmg` | [`src/formats/dmg/mod.rs`](src/formats/dmg/mod.rs) |
| `dng` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `elf` | [`src/elf/mod.rs`](src/elf/mod.rs) |
| `heic` | [`src/formats/isobmff/mod.rs`](src/formats/isobmff/mod.rs) |
| `heif` | [`src/formats/isobmff/mod.rs`](src/formats/isobmff/mod.rs) |
| `icns` | [`src/formats/icns/mod.rs`](src/formats/icns/mod.rs) |
| `jpeg` | [`src/formats/jpeg/mod.rs`](src/formats/jpeg/mod.rs) |
| `macho` | [`src/macho/mod.rs`](src/macho/mod.rs) |
| `mov` | [`src/formats/isobmff/mod.rs`](src/formats/isobmff/mod.rs) |
| `mp4` | [`src/formats/isobmff/mod.rs`](src/formats/isobmff/mod.rs) |
| `mpq` | [`src/formats/mpq/mod.rs`](src/formats/mpq/mod.rs) |
| `nef` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `oci` | [`src/formats/oci/mod.rs`](src/formats/oci/mod.rs) |
| `orf` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `pe` | [`src/pe/mod.rs`](src/pe/mod.rs) |
| `pef` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `png` | [`src/formats/png/mod.rs`](src/formats/png/mod.rs) |
| `rw2` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `tar` | [`src/formats/tar/mod.rs`](src/formats/tar/mod.rs) |
| `tiff` | [`src/formats/tiff/mod.rs`](src/formats/tiff/mod.rs) |
| `wasm` | [`src/formats/wasm/mod.rs`](src/formats/wasm/mod.rs) |
| `zip` | [`src/formats/zip/mod.rs`](src/formats/zip/mod.rs) |

A printable ISO brand that is not in this table keeps that brand as the type word.
The word `isobmff` means the brand is not text.

Enter opens one member of the current file.
That member stays closed until that enter.
A known file uses its normal page.
The next enter opens one file inside that page.
A 7z archive and an MPQ archive do not open a member.

A deflate member, a gzip layer, and a zlib block must fit in 1 MiB after inflate.
The compressed input must fit in 8 MiB.

An APFS part states that this reader does not list its files.

A slow open shows a spinner and the byte count.
Esc stops that open.

## Why does it exist?

ELF, Mach-O, and PE use different words for the same start fact.
`bininfo` uses one word for that fact on each format.
One claim can check that fact on each format.
A failed claim exits 1.

## Other tools

Each tool below does one part of that job.

| tool | formats | job | missing |
| --- | --- | --- | --- |
| [`llvm-readobj`](https://llvm.org/docs/CommandGuide/llvm-readobj.html) | ELF, Mach-O, COFF | Raw headers and dynamic tags. | The shared start words. A claim file. |
| [`rabin2`](https://book.rada.re/tools/rabin2/intro.html) | Many formats. | Interpreter, libraries, and flags. | The shared start words. A claim file. |
| [`knife`](https://github.com/bl4ckr0ss3/knife) | ELF, Mach-O, PE | Imports, hashes, and disassembly. | The teaching page. A claim check. |
| [`eu-elfclassify`](https://man.archlinux.org/man/eu-elfclassify.1.en) | ELF | Exit 0 when the file matches a type flag. | Mach-O and PE. |
| [`annocheck`](https://sourceware.org/annobin/annobin.html/Annocheck.html) | ELF | Exit on a hardening profile. | Mach-O, PE, and the link list. |
| [`checksec`](https://github.com/slimm609/checksec) | ELF | Hardening flags. | Mach-O and PE. |
| [`readelf`](https://sourceware.org/binutils/docs/binutils/readelf.html) `-d` | ELF | `NEEDED` and the interpreter. | Mach-O and PE. |
| [`ldd`](https://man.archlinux.org/man/ldd.1.en) | ELF | Libraries the loader would open. | The header page. It can run the loader. |
| [`otool`](https://keith.github.io/xcode-man-pages/otool.1.html) `-L` | Mach-O | Linked libraries. | ELF and PE. |
| [`dumpbin`](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference) `/imports` | PE | Imported DLLs. | ELF and Mach-O. |

[`llvm-readobj`](https://llvm.org/docs/CommandGuide/llvm-readobj.html) is the closest reader.
[`eu-elfclassify`](https://man.archlinux.org/man/eu-elfclassify.1.en) is the closest check.

## Install the command

Clone this repo. Cargo writes the `bininfo` command.

```
cargo install --path .
```

The crate is not on crates.io. `publish` is false.

## Use the library

The same repo is a library. The command calls that library.
Each type in the list above has one reader.
`claim` checks one claim.
`open` reads one file.

A Rust project can depend on a local checkout.

```
bininfo = { path = "../bininfo" }
```

```rust
let bytes = std::fs::read(path)?;
let file = bininfo::open(&bytes, false)?;
let page = bininfo::render(path, &file, false, false);
let facts = bininfo::facts(path, &file, &bininfo::current_host())?;
let claims = bininfo::claim::parse(&["hermetic".to_string()])?;
let misses = bininfo::claim::judge(&facts, &claims);
```

`rows` on `open` keeps symbol rows. `json` on `render` prints one JSON object.

## How to use the command

Build with Cargo.
Run the tool from this directory.

```
cargo run --quiet -- <file>
```

Put each flag before the file name.

```
cargo run --quiet -- [--json] [--symbols] [--check] [--expect <claim>] <file>
cargo run --quiet -- [--json] --claims <file>
cargo run --quiet -- [--json] --policy <file> <file>
```

A common `needed` name has a trailing note.
The note names what that library provides.
An unknown name has no note.
`delay` uses the same notes.

`--json` prints one JSON object.
`--symbols` prints each symbol row.
`--check` checks the `hermetic` claim.
`--expect` checks one claim.
Repeat `--expect` for each claim.
`--claims` checks each line in a claim file.
Add `--json` to print a check as JSON.
`--policy` reads a policy file and judges embedded certificates.
It does not print the page.
A deny exits 1.
A warn keeps exit 0.

```
cargo run --quiet -- --policy policies/distrusted.policy <file>
```

A rule line has this shape.

```
deny <id> spki <64 hex characters> :: <message>
warn <id> issuer "<common name>" :: <message>
```

`spki` is the preferred match key.
It is the SHA-256 of the public key bytes in the certificate.

`hermetic` passes when all three facts are true.

- `kind` is `static` or `static-pie`.
- `interp` is null.
- `needed` is empty.

This check does not read `dlopen`.

A `kind` value is `static`, `dynamic`, `dynamic-pie`, `static-pie`, `shared`, `rel`, or `other`.
Repeat `needed=` once for each library.
`interp=null` means the file has no loader.

```
cargo run --quiet -- --expect kind=dynamic-pie --expect needed=libtiny.so <file>
```

A terminal adds color to the page.
`NO_COLOR` keeps the page plain.

Build the samples with Zig.

```
./show.sh
./check.sh
```

`./show.sh` prints JSON for each sample.
`./check.sh` checks `claims.txt`.
