# binvet

`binvet <file>` prints one page for one binary. The file can be ELF, Mach-O, or PE. The page has type, load, symbols, sizes, where, and sections. ELF can add abi. Mach-O can add build and dylib. PE can add two version lines. A `#` note follows each value. A terminal adds color. `NO_COLOR` keeps the page plain.

`binvet --json <file>` prints one JSON object. `format` is `elf`, `macho`, or `pe`. `./show.sh` passes `--json`.

# Other tools

`binvet` uses the same start words for ELF, Mach-O, and PE. A claim exits 1 when the file breaks that claim. The tools below each do one part of that job.

| tool | formats | job | missing |
| --- | --- | --- | --- |
| `llvm-readobj` | ELF, Mach-O, COFF | Raw headers and dynamic tags. | The shared start words. A claim file. |
| `rabin2` | Many formats. | Interpreter, libraries, and flags. | The shared start words. A claim file. |
| `knife` | ELF, Mach-O, PE | Imports, hashes, and disassembly. | The teaching page. A claim check. |
| `eu-elfclassify` | ELF | Exit 0 when the file matches a type flag. | Mach-O and PE. |
| `annocheck` | ELF | Exit on a hardening profile. | Mach-O, PE, and the link list. |
| `checksec` | ELF | Hardening flags. | Mach-O and PE. |
| `readelf -d` | ELF | `NEEDED` and the interpreter. | Mach-O and PE. |
| `ldd` | ELF | Libraries the loader would open. | The header page. It can run the loader. |
| `otool -L` | Mach-O | Linked libraries. | ELF and PE. |
| `dumpbin /imports` | PE | Imported DLLs. | ELF and Mach-O. |

`llvm-readobj` is the closest reader. `eu-elfclassify` is the closest check.

Zig writes most files into `samples/out`. Git does not store that directory.

`hermetic` is `yes` when the header names no other file.

| file | hermetic | what the header shows |
| --- | --- | --- |
| `rel-x86-64.o` | no | `REL`. No program headers. |
| `exec-x86-64` | yes | `EXEC`. No loader. Kind `static`. |
| `static-pie-x86-64` | yes | `DYN`. No loader. Kind `static-pie`. |
| `lib-x86-64.so` | no | `DYN`. A shared library. It names no library. |
| `libtiny.so` | no | A shared library. The next three files open this name. |
| `libneed.so` | no | A shared library. It opens `libtiny.so`. |
| `dyn-x86-64` | no | `EXEC`. A loader opens `libtiny.so`. Kind `dynamic`. |
| `dyn-pie-x86-64` | no | `DYN`. A loader opens `libtiny.so`. Kind `dynamic-pie`. |
| `exec-i386` | yes | `ELF32`. Kind `static`. |
| `exec-aarch64` | yes | Machine AArch64. Kind `static`. |
| `exec-powerpc64` | yes | Big-endian. Kind `static`. |
| `rel-aarch64.o` | no | Mach-O object. Kind `rel`. |
| `libtiny.dylib` | no | Mach-O shared library. Loader `/usr/lib/dyld`. It opens `libSystem.B.dylib`. |
| `static-aarch64` | yes | Mach-O program. No loader. Kind `static`. |
| `static-pie-aarch64` | yes | Mach-O program. No loader. Kind `static-pie`. |
| `dyn-fixed-aarch64` | no | Mach-O program. Kind `dynamic`. Loader `/usr/lib/dyld`. |
| `dyn-pie-aarch64` | no | Mach-O program. Kind `dynamic-pie`. The loader is `/usr/lib/dyld`. |
| `dyn-aarch64` | no | Mach-O program. Kind `dynamic-pie`. It opens `libtiny.dylib` and `libSystem.B.dylib`. |
| `rel-x86-64.obj` | no | COFF object. Kind `rel`. |
| `exec-x86-64.exe` | yes | PE32+. No imported DLL. Kind `static-pie`. |
| `static-x86-64.exe` | yes | PE32+. No imported DLL. Kind `static`. |
| `exec-i386.exe` | yes | PE32. Kind `static-pie`. |
| `tiny.dll` | no | PE DLL. Kind `shared`. |
| `dyn-x86-64.exe` | no | PE32+. It opens `tiny.dll`. Kind `dynamic`. |
| `dyn-pie-x86-64.exe` | no | PE32+. It opens `tiny.dll`. Kind `dynamic-pie`. |

Zig links every macOS program to `/usr/lib/dyld`. `static-aarch64` and `static-pie-aarch64` are minimal headers. They show the two hermetic Mac kinds.

`dyn-fixed-aarch64` is `dyn-pie-aarch64` with the `MH_PIE` bit clear.

Zig sets `DYNAMIC_BASE` on Windows. `static-x86-64.exe` is `exec-x86-64.exe` with that bit clear. `dyn-x86-64.exe` is `dyn-pie-x86-64.exe` with that bit clear.

`load.kind` names how the file starts. The same word has the same meaning for ELF, Mach-O, and PE. `load.interp` is the loader path. `null` means the file starts itself. A PE file has no loader path. `load.needed` lists the library names. The note names the format record: `DT_NEEDED`, `LC_LOAD_DYLIB`, or `IMAGE_IMPORT_DESCRIPTOR`.

`load.runpath` lists `DT_RUNPATH` directories. A colon splits one ELF search string. `load.rpath` lists `DT_RPATH` or `LC_RPATH` directories. Mach-O has no `RUNPATH` record. PE has no search-path record. Those lists stay empty. A directory is not a library name.

`load.delay` lists PE delay-load DLL names. The loader opens them on the first call. ELF and Mach-O have no delay-import record.

`load.dlopen` is true when an ELF `DT_NEEDED` entry is `libdl.so`. That entry means the file can call `dlopen`. It does not name the library. Mach-O and PE use `null`. `libSystem` and `kernel32` do not prove a later call.

The symbols group counts loader symbols. ELF prints undef, defined, verneed, and symtab. Mach-O prints chained_fixups or bind, plus exports and symtab. PE prints import, ordinal, export, and coff_symbols. `binvet --symbols <file>` prints the rows. `entry_name` is the symbol whose value equals the entry. It is null when no symbol matches.

`build` names the platform, the minimum OS, and the SDK. The record is `LC_BUILD_VERSION`. `dylib` lists compatibility_version and current_version. The list uses the same order as needed.

A fat Mach-O is `universal`. It is `universal2` when one slice is x86-64 and one slice is AArch64. A fat Mach-O opens each slice. `slices` lists the load for that slice. `load` is present when every slice has the same load facts. A closed slice has filetype `null`. The note is `This slice does not open.` `cpusubtype_name` separates `ARM64_ALL`, `ARM64E`, and `ARM64E_X1`. Those three share the AArch64 CPU type. The low 8 bits name the variant. High bits are capability flags.

# Check a file

`binvet --check <file>` checks that claim.

The check passes when all three facts are true.

- `kind` is `static` or `static-pie`.
- `interp` is null.
- `needed` is empty.

The program then starts itself. The header closure is this file.

The check fails for a loader, a library name, a shared library, or an object file. The exit code is 1. The report names each miss.

This check does not read `dlopen`. It does not open the named libraries. The report adds a host group. That group does not change the hermetic result. `verneed` on that report is skip.

A dynamic file can still make a hermetic run when you ship each named file. `--check` does not prove that you shipped them.

`binvet --expect kind=dynamic-pie --expect needed=libtiny.so <file>` checks those claims. `--json` prints one object.

`claims.txt` records the claim for each sample. `./check.sh` builds the samples and checks that file.

`samples/start.c` is an empty `_start`. `samples/tiny.c` defines `tiny`. `samples/need.c` calls `tiny`. `samples/call.c` calls `tiny` from `_start`. `samples/win-dll.c` is the Windows DLL. `samples/win-call.c` imports `tiny`.

Zig is required. Run `./show.sh` or `./check.sh` from this directory.

`yq` reads the page. `jq` reads the JSON stream.

```
cargo run --quiet -- samples/out/exec-x86-64 | yq '.type.e_type'
```

```
cargo run --quiet -- samples/out/dyn-pie-x86-64 | yq '.load'
```

```
cargo run --quiet -- samples/out/dyn-pie-x86-64.exe | yq '.load.kind'
```

```
cargo run --quiet -- --check samples/out/exec-x86-64 | yq '.result'
```

```
./show.sh | jq -c 'select(.e_type == "DYN") | {file, e_entry}'
```
