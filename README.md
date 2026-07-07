<div align="center">

# HexSpell

**A lightweight, dependency-free Rust library for parsing and patching PE, ELF, and Mach-O executables.**

<img src="https://github.com/M3str3/HexSpell/assets/62236987/8d5d500a-acb1-45d0-a63e-ec610b5e5ccc" alt="HexSpell" width="400">

[![Crates.io](https://img.shields.io/crates/v/hexspell.svg)](https://crates.io/crates/hexspell)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

## Overview

HexSpell is a small parsing library for executable binaries. It has **no runtime dependencies** —
only the Rust standard library — so it stays easy to embed, audit, and ship.

Parse PE, ELF, and Mach-O files (including FAT Mach-O), read headers and tables, and write changes
back to disk when you need to patch an executable.

- **Zero dependencies** — no external crates at runtime.
- **Lightweight** — focused on parsing and patching; no heavy framework around the formats.
- **Multi-format** — PE (Windows), ELF (Linux), and Mach-O (macOS) in one crate.
- **Parse and patch** — read entry points, sections, imports, exports, and more; update headers and write the file back with `write_file`.
- **Structural edits** — insert sections and load segments, sync layout, apply relocations.
- **Lazy parsers** — imports, exports, TLS, exceptions, symbols, and other tables parsed on demand.
- **Endianness-aware** — ELF and Mach-O byte order handled via `ByteOrder`.

See [`docs/coverage.md`](docs/coverage.md) for exactly what is modeled per format.

## Installation

```bash
cargo add hexspell
```

Or add it manually to `Cargo.toml`:

```toml
[dependencies]
hexspell = "1.0"
```

## Quick start

```rust
use hexspell::pe::PE;

fn main() {
    let mut pe = PE::from_file("app.exe").expect("failed to parse PE");

    // Read header fields from the parsed file.
    println!("architecture: {}", pe.architecture());
    println!("entry point:  {:#x}", pe.optional_header.entry_point.value);

    // Patch the entry point and write the modified file back to disk.
    pe.optional_header
        .entry_point
        .update(&mut pe.buffer, 0x36D4)
        .unwrap();

    pe.write_file("app-patched.exe").expect("failed to write PE");
}
```

ELF and Mach-O follow the same pattern (`ELF::from_file`, `MachO::from_file`). For big-endian
binaries, use `Field::update_with` with the format's `byte_order()`.

## Examples

Reading key header fields per format:

```rust
use hexspell::pe::PE;

let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
println!("PE type:     {:?}", pe.optional_header.pe_type().unwrap());
println!("checksum:    {:#010x}", pe.optional_header.checksum.value);
println!("sections:    {}", pe.coff_header.number_of_sections.value);
println!("size_of_img: {:#x}", pe.optional_header.size_of_image.value);
```

```rust
use hexspell::elf::ELF;

let elf = ELF::from_file("tests/samples/linux").unwrap();
println!("entry:      {:#x}", elf.header.entry.value);
println!("byte order: {:?}", elf.byte_order().unwrap());
println!("ph / sh:    {} / {}", elf.header.ph_num.value, elf.header.sh_num.value);
```

```rust
use hexspell::macho::MachO;

let macho = MachO::from_file("tests/samples/machO-OSX-x86-ls").unwrap();
println!("load commands: {}", macho.header.ncmds.value);
println!("byte order:    {:?}", macho.byte_order());
println!("first segment: {}", macho.segments[0].name());
```

Inserting a new PE section (for example, to inject code):

```rust
use hexspell::pe::PE;
use hexspell::pe::section::{NewSection, CODE, READ, EXECUTE};

let mut pe = PE::from_file("tests/samples/sample1.exe").unwrap();

pe.insert_section(NewSection {
    name: ".shell".to_string(),
    data: vec![0x90; 64], // your payload here
    characteristics: CODE | READ | EXECUTE,
})
.unwrap();

// Point the entry to the start of the new section.
let new_va = pe.sections.last().unwrap().virtual_address.value;
pe.optional_header
    .entry_point
    .update(&mut pe.buffer, new_va)
    .unwrap();

pe.write_file("tests/out/modified.exe").unwrap();
```

More runnable examples and per-format walkthroughs live in the [user guide](docs/guide.md).

## Documentation

- [User guide](docs/guide.md) — design principles, per-format examples, error handling.
- [Layout accessors](docs/layout.md) — `field()` / `field_mut()` on ELF/Mach-O layout enums.
- [Coverage matrix](docs/coverage.md) — what is modeled vs not, per format.
- [Changelog](CHANGELOG.md) — notable changes per release.

## Contributing

Issues and pull requests are welcome — [open an issue](https://github.com/M3str3/HexSpell/issues) to
report a bug or discuss a change. Contributors and agents should follow the conventions in
[`AGENTS.md`](AGENTS.md) (tests required, `cargo fmt` + `cargo test` before finishing, no runtime
dependencies).

## License

Distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
