# Changelog

## [0.0.3] - 2024-09-23
### Fixed
#### PE
- [**Bug #5**](https://github.com/M3str3/HexSpell/issues/5): Fixed overflow in the `calc_checksum` function. The `checksum` variable was previously a `u32`, which could lead to overflow during the checksum calculation in PE files. The fix now uses `u64` during the calculation to prevent overflow, but the function still returns a `u32` as expected.
- [**Bug #4**](https://github.com/M3str3/HexSpell/issues/4): Adjusted `sizeofheaders` when adding a new section with `add_section`. The previous implementation did not account for the case where the new section could not fit within the existing `sizeofheaders`. The fix ensures that if the new section doesn't fit, `sizeofheaders` is increased and aligned with `filealignment`, pushing back the content, including the entry point, to make space.

## [0.0.2] - 2024-09-14
### Added
- New examples for PE, ELF, and Mach-O in the `readme.md`.
- New MachO binary for testing.
- Added basic integration and testing for Mach-O files.

### Refactored
- **Tests (MachO & ELF)**: Simplified test cases by using `is_empty()` instead of `!= ""`.
- **Utils**: Refactored utility functions to use `map` for byte conversion in extraction functions.
- **Field struct**: Updated buffer parameter from `Vec<u8>` to `&mut [u8]`.
- **PE/Header**: Moved from using `to_string` to implementing the `fmt::Display` trait for cleaner string formatting.
- **General formatting**: Applied `cargo fmt` to format code consistently.
  
### Fixed
- Fixed spelling mistakes in various files.
  
### Chore
- Added `rustfmt.toml` file to define code formatting rules.
- Removed unnecessary type conversions in the PE module.

### Documentation
- Updated `tests/readme.md` with more documentation and examples.
- Added new generator script to automate the creation of `tests.toml` files.

## [0.0.1] - 2024-05-22
### Added
- Initial support for PE (Portable Executable) format.
- Initial support for ELF (Executable and Linkable Format).
- Basic tests for PE and ELF file structures.
- Core functionality for reading and parsing PE and ELF headers.
