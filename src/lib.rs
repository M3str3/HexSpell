//! # HexSpell
//!
//! HexSpell is a collection of helpers for inspecting and mutating executable formats. It focuses
//! on providing a small, predictable API that mirrors the underlying file layout so that programs
//! can tweak headers or sections without rebuilding the whole file.
//!
//! The crate is split into dedicated modules for the **PE**, **ELF**, and **Mach-O** formats. Each
//! module exposes types for reading a binary from disk, modifying its fields in place, and writing
//! the result back. Common building blocks such as [`field::Field`] and shared error definitions
//! live in sibling modules.
//!
//! Additional prose documentation is in [`docs/guide.md`](https://github.com/M3str3/HexSpell/blob/main/docs/guide.md)
//! and [`docs/layout.md`](https://github.com/M3str3/HexSpell/blob/main/docs/layout.md).
//!
//! # Examples
//!
//! ```
//! use hexspell::pe::PE;
//! let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
//! println!("entry: {:#x}", pe.optional_header.entry_point.value);
//! ```

// Standard
pub mod errors;
pub mod field;
pub mod utils;

pub mod elf; // ELF
pub mod macho;
/// Executable Formats
/// ==================
pub mod pe; // PE (Portable Executable) // Mach-O
