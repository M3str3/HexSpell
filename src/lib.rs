//! # HexSpell
//!
//! HexSpell is a collection of helpers for inspecting and mutating
//! executable formats. It focuses on providing a small, predictable API
//! that mirrors the underlying file layout so that programs can tweak
//! headers or sections without rebuilding the whole file.
//!
//! The crate is split into dedicated modules for the **PE**, **ELF**, and
//! **Mach-O** formats. Each module exposes types for reading a binary from
//! disk, modifying its fields in place, and writing the result back. Common
//! building blocks such as [`Field`](crate::field::Field) and shared error
//! definitions live in sibling modules.
//!
//! Basic usage revolves around choosing a format module and loading a file:
//!
//! ```
//! use hexspell::pe::PE;
//! let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
//! println!("sections: {:?}", pe.header.entry_point.value);
//! ```
//!
//! From there values can be changed using the provided `Field` helpers and
//! persisted with `write_file`.

// Standard
pub mod errors;
pub mod field;
pub mod utils;


/// Executable Formats
/// ==================
pub mod pe;     // PE (Portable Executable)
pub mod elf;    // ELF
pub mod macho;  // Mach-O
