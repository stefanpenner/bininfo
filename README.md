<!--
---
why: This file tells a reader what bininfo prints and how to run it.
uses: a reader
how: The reader opens this file in the repo.
---
-->

# bininfo

## What is this?

`bininfo` reads one ELF, Mach-O, or PE file.
It prints one page for that file.
The page uses the same words for each format.
The page has type, load, symbols, sizes, where, and sections.

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

## How to use it

Build with Cargo.
Run the tool from this directory.

```
cargo run --quiet -- <file>
```

Put each flag before the file name.

```
cargo run --quiet -- [--json] [--symbols] [--check] [--expect <claim>] <file>
cargo run --quiet -- [--json] --claims <file>
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
