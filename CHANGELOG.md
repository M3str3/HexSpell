# Changelog

***All notable changes to this project will be documented in this file.***

## [0.0.4](https://github.com/M3str3/HexSpell/pull/9) - 2025-08-02

### Added
- Added testing for ***PE***, ***ELF*** & ***Mach-O*** to ensure errors are raised on invalid formats.

### Fixed
- In ***ELF*** & ***Mach-O*** parsers, conversion errors now propagate to `FileParseError::BufferOverflow` instead of panicking.
- In ***PeSection*** string extraction, invalid ranges errors now propagate to  `FileParseError::BufferOverflow` instead of panicking.
- In ***Field*** values that exceed the attribute's limits now propagate `FileParseError::BufferOverflow` instead of panicking.



## [0.0.3](https://github.com/M3str3/HexSpell/pull/6) - 2024-09-23

### Fixed
- **Bug #5**: Prevented overflow in `calc_checksum` by performing calculations in `u64` before casting back to `u32`. ([#5](https://github.com/M3str3/HexSpell/issues/5))  
- **Bug #4**: When adding a new section via `add_section`, ensure `sizeofheaders` grows (and is aligned to `filealignment`) if the section doesn’t fit, shifting the rest of the file (including the entry point) accordingly. ([#4](https://github.com/M3str3/HexSpell/issues/4))



## [0.0.2](https://github.com/M3str3/HexSpell/pull/3) - 2024-09-14

### Added
- Initial support for ***Mach-O*** format.  
- Additional ***Mach-O*** test binary.  
- New examples for PE, ELF and Mach-O in `README.md`.  

### Changed
- Simplified ***Mach-O*** & ***ELF*** tests to use `is_empty()` instead of comparing with `!= ""`.  
- Refactored utility functions to use `Iterator::map` for byte conversions.  
- Updated `Field` struct to accept `&mut [u8]` instead of `Vec<u8]`.  
- In ***PE*** module, replaced `to_string` calls with `fmt::Display` implementations for cleaner formatting.  
- Added `rustfmt.toml` to define project-wide formatting rules and ran `cargo fmt`.  
- Removed unnecessary type conversions in the ***PE*** code.

### Fixed
- Corrected typos and spelling mistakes throughout the codebase.

### Documentation
- Expanded `tests/readme.md` with more examples and explanations.  
- Introduced a generator script to automate creation of `tests.toml`.



## [0.0.1](https://github.com/M3str3/HexSpell/pull/2) - 2024-05-22

### Added
- Initial support for ***PE*** (Portable Executable) format.  
- Initial support for ***ELF*** (Executable and Linkable Format).  
- Core parsing functionality for ***PE*** & ***ELF*** headers.  
- Basic unit tests for ***PE*** & ***ELF*** structures.
