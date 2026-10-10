# ELF headers

`herman <file>` prints five groups. The groups are type, load, sizes, where, and sections. The file can be ELF, Mach-O, or PE. A `#` note follows each value. A terminal adds color. `NO_COLOR` keeps the page plain.

`herman --json <file>` prints one JSON object. `format` is `elf`, `macho`, or `pe`. `./show.sh` passes `--json`.

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

`load.kind` names how the file starts. The same word has the same meaning for ELF, Mach-O, and PE. `load.interp` is the loader path. `null` means the file starts itself. A PE file has no loader path. `load.needed` lists the library names.

`load.hermetic` is true when the header names no other file. The kind is then `static` or `static-pie`. `load.says` is one sentence for those facts.

# Check a file

`herman --check <file>` checks that claim.

The check passes when all three facts are true.

- `kind` is `static` or `static-pie`.
- `interp` is null.
- `needed` is empty.

The program then starts itself. The header closure is this file.

The check fails for a loader, a library name, a shared library, or an object file. The exit code is 1. The report names each miss.

This check does not read `dlopen`. It does not open the named libraries.

A dynamic file can still make a hermetic run when you ship each named file. `--check` does not prove that you shipped them.

`herman --expect kind=dynamic-pie --expect needed=libtiny.so <file>` checks those claims. `--json` prints one object.

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
cargo run --quiet -- --check samples/out/dyn-pie-x86-64 | yq '.says'
```

```
./show.sh | jq -c 'select(.e_type == "DYN") | {file, e_entry}'
```
