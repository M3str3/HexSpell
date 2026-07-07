# HexSpell

HexSpell is a dependency-free Rust library for parsing and patching **PE**, **ELF**, and **Mach-O**
binaries. The API mirrors the on-disk layout: every exposed header field is a [`Field`] with the
real `offset` and `size` in the file buffer.

## Design principles

1. **1:1 with the file format** — fields live where the specification places them (`ei_data` in the
   ELF header, `machine` in the COFF header, segment names as raw bytes, and so on).
2. **Explicit buffer** — `PE`, `ELF`, and `MachO` own a `buffer: Vec<u8>`. Patching always passes
   that buffer into `Field::update` or layout accessors.
3. **Small utility surface** — helpers such as `insert_section` perform real structural edits; they
   do not hide the underlying tables.

## Core types

| Type | Role |
|------|------|
| [`Field`] | Value + absolute offset + on-disk size |
| [`FixedBytes`] | Fixed-size byte array (section names, `e_ident`, Mach-O `segname`) |
| [`ByteOrder`] | ELF / Mach-O endianness helpers |
| [`FileParseError`] | Shared parse and patch errors |

See [docs/layout.md](layout.md) for `field()` / `field_mut()` accessors on program headers,
section headers, and segments.

## PE (Windows)

PE files are modeled as:

```
dos_header → coff_header → optional_header → sections[]
```

```rust
use hexspell::pe::PE;

let pe = PE::from_file("app.exe")?;
println!("arch: {}", pe.architecture());
println!("entry: {:#x}", pe.optional_header.entry_point.value);

pe.optional_header
    .entry_point
    .update(&mut pe.buffer, 0x1000)?;

pe.write_file("app-patched.exe")?;
```

Imports, exports, TLS, exceptions, symbols, and other data directories are available via lazy parsers on [`PE`] (for example [`PE::imports`], [`PE::exports`], [`PE::tls`], [`PE::coff_symbols`]). To change the load address and patch base relocations in the buffer, use [`PE::apply_image_base`].

Insert a section:

```rust
use hexspell::pe::{PE, section::{NewSection, CODE, READ, EXECUTE}};

let mut pe = PE::from_file("app.exe")?;
pe.insert_section(NewSection {
    name: ".data".into(),
    data: vec![0x90; 64],
    characteristics: CODE | READ | EXECUTE,
})?;
pe.write_file("app-section.exe")?;
```

## ELF (Linux)

ELF endianness is stored in `header.ei_data`. Use [`ELF::byte_order`] as a convenience alias.

```rust
use hexspell::elf::ELF;

let mut elf = ELF::from_file("./a.out")?;
let order = elf.byte_order()?;

elf.header
    .entry
    .update_with(&mut elf.buffer, 0x2000, order)?;

println!("phdr count: {}", elf.header.ph_num.value);
elf.write_file("a.out.patched")?;
```

Read a program header offset without mutating the container:

```rust
let offset = elf.program_headers[0].p_offset();
```

Patch it:

```rust
elf.program_headers[0]
    .p_offset_mut()
    .update_with(&mut elf.buffer, 0x4000, order)?;
```

## Mach-O (macOS)

Mach-O has no endianness byte in the header; byte order is derived from the `magic` bytes on disk.

```rust
use hexspell::macho::MachO;

let macho = MachO::from_file("binary")?;
println!("byte order: {:?}", macho.byte_order());
println!("first segment: {}", macho.segments[0].name());
```

FAT binaries are unpacked automatically; the parsed object refers to the embedded thin Mach-O.

## Error handling

All parsers return [`Result`]. Typical variants:

- [`FileParseError::InvalidFileFormat`] — bad magic, unknown PE optional header magic, etc.
- [`FileParseError::BufferOverflow`] — truncated file or string longer than field size.
- [`FileParseError::ValueTooLarge`] — numeric value does not fit in the on-disk field width.

## What is not covered yet

ELF dynamic linking, Mach-O typed load commands, and full PE layout rebuild after structural edits are not complete. See [`TODO.md`](https://github.com/M3str3/HexSpell/blob/main/TODO.md) for the gap matrix.

[`Field`]: crate::field::Field
[`FixedBytes`]: crate::field::FixedBytes
[`ByteOrder`]: crate::field::ByteOrder
[`FileParseError`]: crate::errors::FileParseError
[`Result`]: crate::errors::Result
[`ELF::byte_order`]: crate::elf::ELF::byte_order
[`PE`]: crate::pe::PE
[`PE::imports`]: crate::pe::PE::imports
[`PE::exports`]: crate::pe::PE::exports
[`PE::tls`]: crate::pe::PE::tls
[`PE::coff_symbols`]: crate::pe::PE::coff_symbols
[`PE::apply_image_base`]: crate::pe::PE::apply_image_base
