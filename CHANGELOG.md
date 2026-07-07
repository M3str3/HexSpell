# Changelog

<div align="center">
  <i>
    All notable changes to this project will be documented in this file.
  </i>
</div>

> **Changelog Format**
>
> - Each release is grouped by version.
> - Inside each version, changes are grouped by module in this order:
>   * General > PE > ELF > Mach-O
> - Inside each module, changes are listed by type in this order:
>   * Added > Changed > Fixed > Documentation > Chore 
>
> **Entry example:**
> ## Version
> - **Module**
>     - *Added*: Your message here using `markdown`.


## [Unreleased]

- **PE**
    - *Added*: `OptionalHeader::active_data_directory_count` / `has_data_directory`; parse respects `number_of_rva_and_sizes`.
    - *Added*: Full export table (`FunctionExport`, forwarders, `ordinal_only_exports`), bound import (`bound`), delay-load import (`delay`).
    - *Added*: `relocation::apply_base_relocations`, `PE::apply_image_base`.
    - *Added*: TLS (`tls`), exception / `RUNTIME_FUNCTION` (`exception`), COFF symbols (`symbol`), section COFF relocs (`section_reloc`), load config base fields (`load_config`), debug directory (`debug`), resource tree (`resource`).
    - *Added*: `PE::bound_imports`, `delay_imports`, `tls`, `exceptions`, `coff_symbols`, `section_relocations`, `load_config`, `debug_directory`, `resources`, `sync_data_directory_rva`, `sync_data_directory_size`.
    - *Changed*: `rva_to_offset` maps only RVAs covered by `SizeOfRawData` (file-backed ranges).
- **ELF**
    - *Added*: Section semantics — `ELF::section_name`, `section_data` (`SHT_NOBITS` aware), `section_index_by_name`, `section_by_name`; `SectionType` enum + `SectionHeaderEntry::section_type` and `SHT_*` constants.
    - *Added*: Program header typing — `SegmentType` enum + `ProgramHeaderEntry::segment_type` and `PT_*` constants (`PT_DYNAMIC`, `PT_INTERP`, `PT_NOTE`, `PT_GNU_*`, etc.).
    - *Added*: Symbol tables (`symbol`) — `SymbolEntry` (`Elf32_Sym` / `Elf64_Sym`), `SymbolTable` with name resolution; `ELF::symbols` (`.symtab`) and `ELF::dynamic_symbols` (`.dynsym`); `STB_*` / `STT_*` constants.
    - *Added*: Dynamic linking (`dynamic`) — `DynamicEntry`, `DynamicTable`, `DynamicTag`, `DT_*` constants; `ELF::dynamic`.
    - *Added*: Relocations (`relocation`) — `RelocationEntry` (`.rel` / `.rela`, ELF32/64) with unpacked `symbol()` / `reloc_type()` / `r_addend()`; `ELF::relocations`.

## [1.0.0] - 2026-07-07

- **General**
    - *Added*: `FixedBytes<N>` type and `Field<FixedBytes<N>>::update` / `update_str` for on-disk byte fields.
    - *Added*: `ByteOrder::from_ei_data` (alias of `from_elf_data`) and `ByteOrder::from_macho_header_bytes`.
    - *Added*: `NumericFieldMut` and `FieldMut` accessors for layout enums (patch semantics without raw `Field` copies).
    - *Added*: `ByteOrder::read_u16/u32/u64` and `write_u16/u32/u64` helpers for parsers.
    - *Changed*: **Breaking** — single `field::ByteOrder` type; removed `elf::header::Endianness` and `macho::header::Endianness`.
- **PE**
    - *Added*: `DosHeader` (`IMAGE_DOS_HEADER`) and `CoffFileHeader` (`IMAGE_FILE_HEADER`) with full `Field` mapping.
    - *Added*: `PE::architecture()` alias delegating to `coff_header.machine`.
    - *Added*: `OptionalHeader::magic: Field<u16>` and `OptionalHeader::pe_type()` derived from magic.
    - *Added*: `NewSection`, `insert_section`, `insert_section_raw`; section flag constants (`CODE`, `READ`, `EXECUTE`, etc.).
    - *Changed*: **Breaking** — `PE` exposes `dos_header`, `coff_header`, `optional_header`; `architecture` and `number_of_sections` removed from optional header (COFF is canonical).
    - *Changed*: **Breaking** — `PeSection.name` is `Field<FixedBytes<8>>` (use `name_str()` for display).
    - *Changed*: **Breaking** — removed `generate_section_header` and `add_section` (use `insert_section`).
- **ELF**
    - *Added*: `ElfHeader` fields `ei_mag`, `ei_class`, `ei_data`, `ei_version`, `ei_pad` as canonical `Field`s.
    - *Added*: `ElfHeader::class()` helper derived from `ei_class`.
    - *Added*: `ProgramHeaderEntry` (`Phdr32` / `Phdr64`) and `SectionHeaderEntry` (`Shdr32` / `Shdr64`) with field accessors.
    - *Added*: `ELF::byte_order()`, `insert_section` (append-only), `insert_pt_load` (append-only), `NewSection`, `NewPtLoad`.
    - *Changed*: **Breaking** — removed `ELF.byte_order` field and `ElfHeader.ident` / `ElfHeader.class` fields; `byte_order()` returns `Result` from `header.ei_data`.
    - *Changed*: **Breaking** — `program_headers` and `section_headers` use layout enums; `header.endianness` removed (use `elf.byte_order()`).
    - *Changed*: layout field API — read `ph.p_offset()`, patch `ph.p_offset_mut()` (removed `*_value()` duplicates).
- **Mach-O**
    - *Added*: `SegmentEntry` (`Segment32` / `Segment64`) with field accessors; `MachO::byte_order()`, `insert_segment`, `NewSegment`.
    - *Changed*: **Breaking** — removed `MachO.byte_order` field; `byte_order()` derives from header magic bytes on disk.
    - *Changed*: **Breaking** — segment `segname: Field<FixedBytes<16>>` replaces `name: String` (`name()` remains as view).
    - *Changed*: **Breaking** — `segments` use `SegmentEntry`; `header.endianness` removed (use `macho.byte_order()`).
    - *Changed*: layout field API — read `seg.vmaddr()`, patch `seg.vmaddr_mut()` (removed `*_value()` duplicates).
- **Documentation**
    - *Changed*: `API_DESIGN.md` updated for 1.0 (accessors, insert complexity, migration §8, and 1:1 gap matrix).

## [0.0.5](https://github.com/M3str3/HexSpell/pull/10) - 2025-08-07

- **General**
    - *Added*: Added comprehensive tests for `Field<String>` covering padding, exact fit, overflow, and UTF-8 multibyte handling in section names (see `tests/general.rs`).
    - *Added*: Added tests for `Field<number>` updates verifying successful writes and `FileParseError::ValueTooLarge` errors.
    - *Changed*: `Field<number>::update` now returns `Result` and errors with `FileParseError::ValueTooLarge` if the value does not fit.
    - *Changed*: `Field<String>::update` now accepts `&str` instead of `&String`, reducing unnecessary allocations when updating string fields.
    - *Fixed*: Improved `Field<String>::update` to ensure that when the new value is shorter than the field size, any leftover bytes are properly zeroed out, and UTF-8 multibyte strings are handled correctly. In previous versions, some bytes from the old value could remain in the binary.
    - *Documentation*: Expanded module-level documentation with detailed headers across core modules and tests.
- **PE**
    - *Added*: Added tests for successful and failing writes for **PE** files.
    - *Changed*: Updated internal calls to `Field<number>::update` to propagate `FileParseError::ValueTooLarge` errors.
- **ELF**
    - *Added*: Added `write_file` method for **ELF** format, providing a consistent read/write interface across all formats.
    - *Added*: Added tests for successful and failing writes for **ELF** files.
    - *Added*: Detect `endianness` from header and parse program and section headers with the appropriate byte order. A new value `elf::header::endianness` now exists.
    - *Added*: Added tests for valid and invalid **ELF** headers to ensure `endianness` is handled correctly.
- **Mach-O**
    - *Added*: Added `write_file` method for **Mach-O** format, providing a consistent read/write interface across all formats.
    - *Added*: Added tests for successful and failing writes for **Mach-O** files.
    - *Added*: Detect **Mach-O** endianness from the header and parse load commands and segments with the appropriate byte order, including tests for valid and invalid big-endian headers. A new value `macho::header::endianness` now exists.
    - *Added*: Support parsing **FAT** **Mach-O** binaries and add tests for little-endian and **FAT** headers.
    - *Fixed* [#4](https://github.com/M3str3/HexSpell/issues/4): When adding a new section via `add_section`, ensure `sizeofheaders` grows (and is aligned to `filealignment`) if the section doesn’t fit, shifting the rest of the file (including the entry point) accordingly. ([#4](https://github.com/M3str3/HexSpell/issues/4))

## [0.0.2](https://github.com/M3str3/HexSpell/pull/3) - 2024-09-14

- **General**
    - *Added*: New examples for **PE**, **ELF** and **Mach-O** in `README.md`.
    - *Added*: Added `rustfmt.toml` to define project-wide formatting rules and ran `cargo fmt`.
    - *Changed*: Refactored utility functions to use `Iterator::map` for byte conversions.
    - *Changed*: Updated `Field` struct to accept `&mut [u8]` instead of `Vec<u8]`.
    - *Changed*: Removed unnecessary type conversions in the **PE** code.
    - *Fixed*: Corrected typos and spelling mistakes throughout the codebase.
    - *Documentation*: Expanded `tests/readme.md` with more examples and explanations.
    - *Documentation*: Introduced a generator script to automate creation of `tests.toml`.
- **PE**
    - *Changed*: Replaced `to_string` calls with `fmt::Display` implementations for cleaner formatting.
- **ELF**
    - *Changed*: Simplified tests to use `is_empty()` instead of comparing with `!= ""`.
- **Mach-O**
    - *Added*: Initial support.
    - *Added*: Basic unit tests.
    - *Added*: Additional test binary.

## [0.0.1](https://github.com/M3str3/HexSpell/pull/2) - 2024-05-22

- **PE (Portable Executable)**
    - *Added*: Initial support.
    - *Added*: Core parsing functionality for headers.
    - *Added*: Basic unit tests.
    - *Added*: Additional test binaries (**EXE** and **DLL**) and their source code.
- **ELF (Executable and Linkable Format)**
    - *Added*: Initial support.
    - *Added*: Core parsing functionality for headers.
    - *Added*: Basic unit tests.
    - *Added*: Additional test binary and its source code.
