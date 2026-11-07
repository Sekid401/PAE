# PAE - Personal Assembly Executor

Type assembly, run it, see what changed. Registers and data memory are real and kept between lines (no spyware involved).

## Features

- Run assembly line by line in a REPL, from a file, or straight from the command line
- Registers and flags tracked between runs; zeroed data memory you can read and write
- `--asm` assembles and links a real ELF executable (`--no-elf` for raw machine code)
- Install extra architectures with AAI, the package manager (Keystone has to support them)

## Programs

| Program | Architectures | Runs as |
|---|---|---|
| `pae64` | arm64, x64, mips64 | 64-bit process |
| `pae32` | arm32, x86, mips32 | 32-bit process |
| `aai`   | installs architecture packages for either | |

Architectures your CPU can't run are assembled and shown as bytes only. AAI is for architectures you want, not general software.

## Requirements

- `pae64` needs a **64-bit** Keystone.
- `pae32` needs a **32-bit** Keystone (and a 32-bit toolchain).
- `aai` needs `curl` at run time.

To build both Keystones you need `cmake` and `make`, and two build directories inside the `keystone` folder:

- `keystone/build` for `pae64` (64-bit)
- `keystone/build32` for `pae32` (32-bit)

## Build

```
make           # pae64, pae32, aai
make install   # binaries + package folders
```

Install `pae64` first, or you won't get a cookie.

## Using it

```
pae64                              architecture menu, then the REPL
pae64 --arch=arm64 file.s          run a file
pae64 --asm --arch=arm64 file.s -o out
```

REPL commands: `regs`, `reset`, `set <reg> <value>`, `mem`, `dump`, `poke`, `memload`, `quit`. Type `{` to start a multi-line block and `}` to run it.

## AAI and trust

A package is code that PAE loads and runs, so AAI is strict about where it comes from.

- **https only.** The repo link must start with `https://`, and redirects must stay on https. `file://` is also accepted for a local folder, since it never touches the network.
- **SHA-512 required.** The repo folder must contain a `SHA512SUMS` file. A package with no line in it is skipped, and a download whose SHA-512 doesn't match is thrown away before anything is installed.
- `aai upgrade` checks the hash again, and `aai info` says whether the installed file still matches the package list.

Repo maintainers: build the sums file in each folder (`pae64/`, `pae32/`) after adding or changing a package:

```
cd pae64 && sha512sum *.so > SHA512SUMS
```

Run `aai update` after upgrading AAI itself, because package lists saved by older versions have no hashes and are ignored.

The hash comes from the same repo as the package. It catches a corrupted or swapped download, but it can't protect you from a repo whose owner is malicious or whose server was fully taken over. Only use repos you trust.

## Tips

- Each block runs in its own child process. A crash (SIGSEGV, SIGILL, SIGBUS) only stops that block; registers and data memory stay as they were.
- Use a multi-line block when one line would leave things in a bad state:
  - `setend be` must be switched back with `setend le` in the same block, or PAE's own code reads backwards.
  - `swp` needs a valid address in its register. Point it at data memory, or build the address inside the block.
- Use `--no-elf` with `--asm` for a raw binary instead of an ELF.

## Notes

This all runs on your device. Crashes are real and they get caught, so don't assume this is a simulation.

## License

PAE, AAI and `aai_pkg.h` are free software under the GNU General Public License, version 2. See `LICENSE`.

Copyright (C) 2026 sekid
