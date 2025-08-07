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

- **General**
    - *Added*: Added comprehensive tests for `Field<String>` covering padding, exact fit, overflow, and UTF-8 multibyte handling in section names (see `tests/general.rs`).
    - *Added*: Added tests for successful and failing writes for **PE**, **ELF** and **Mach-O** files.
    - *Added*: Added tests for numeric `Field` updates verifying successful writes and `FileParseError::ValueTooLarge` errors.
    - *Changed*: Numeric `Field::update` now returns `Result` and errors with `FileParseError::ValueTooLarge` if the value does not fit.
    - *Changed*: `Field<String>::update` now accepts `&str` instead of `&String`, reducing unnecessary allocations when updating string fields.
    - *Fixed*: Improved `Field<String>::update` to ensure that when the new value is shorter than the field size, any leftover bytes are properly zeroed out, and UTF-8 multibyte strings are handled correctly. In previous versions, some bytes from the old value could remain in the binary.
- **PE**
    - *Added*: Added `write_file` method for **PE** format, providing a consistent read/write interface across all formats.
    - *Added*: Added tests for successful and failing writes for **PE** files.
    - *Changed*: Updated internal calls to numeric `Field::update` to propagate `FileParseError::ValueTooLarge` errors.
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

## [0.0.4](https://github.com/M3str3/HexSpell/pull/9) - 2025-08-02

- **General**
    - *Added*: Added testing for **PE**, **ELF** & **Mach-O** to ensure errors are raised on invalid formats.
    - *Fixed*: Numeric **Field** updates validate value size and return `FileParseError::ValueTooLarge` when the value cannot fit.
- **PE**
    - *Fixed*: In **PeSection** string extraction, invalid ranges errors now propagate to  `FileParseError::BufferOverflow` instead of panicking.
- **ELF**
    - *Fixed*: Conversion errors now propagate to `FileParseError::BufferOverflow` instead of panicking.
- **Mach-O**
    - *Fixed*: Conversion errors now propagate to `FileParseError::BufferOverflow` instead of panicking.


## [0.0.3](https://github.com/M3str3/HexSpell/pull/6) - 2024-09-23

- **PE**
    - *Fixed* [#5](https://github.com/M3str3/HexSpell/issues/5): Prevented overflow in `calc_checksum` by performing calculations in `u64` before casting back to `u32`. ([#5](https://github.com/M3str3/HexSpell/issues/5))
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
