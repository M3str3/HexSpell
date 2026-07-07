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
//! Read a PE image and inspect the entry point:
//!
//! ```
//! use hexspell::pe::PE;
//!
//! let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
//! println!("arch: {}", pe.architecture());
//! println!("entry: {:#x}", pe.optional_header.entry_point.value);
//! ```
//!
//! Patch a header field in place (`Field` carries the real file offset):
//!
//! ```
//! use hexspell::pe::PE;
//!
//! let mut pe = PE::from_file("tests/samples/sample1.exe").unwrap();
//! let entry_rva = pe.optional_header.entry_point.value;
//! assert_eq!(pe.optional_header.entry_point.size, 4);
//! pe.optional_header
//!     .entry_point
//!     .update(&mut pe.buffer, entry_rva)
//!     .unwrap();
//! ```
//!
//! Lazy parsers expose imports, exports, and other data directories on demand:
//!
//! ```
//! use hexspell::pe::PE;
//!
//! let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
//! let imports = pe.imports().unwrap();
//! assert!(imports
//!     .dlls
//!     .iter()
//!     .any(|dll| dll.dll_name.eq_ignore_ascii_case("KERNEL32.dll")));
//! ```
//!
//! ELF endianness comes from `ei_data`; use [`elf::ELF::byte_order`] when patching:
//!
//! ```
//! use hexspell::elf::ELF;
//!
//! let elf = ELF::from_file("tests/samples/linux").unwrap();
//! let order = elf.byte_order().unwrap();
//! let text = elf.section_index_by_name(".text").unwrap();
//! assert_eq!(elf.section_name(text).unwrap(), ".text");
//! assert_eq!(order, hexspell::field::ByteOrder::Little);
//! ```
//!
//! Mach-O segments and linked dylibs:
//!
//! ```
//! use hexspell::macho::MachO;
//!
//! let macho = MachO::from_file("tests/samples/machO-OSX-x86-ls").unwrap();
//! assert!(!macho.segments.is_empty());
//! let dylibs = macho.linked_dylibs().unwrap();
//! assert!(dylibs.iter().any(|path| path.contains("libSystem")));
//! ```
//!
//! Write the patched buffer back to disk:
//!
//! ```no_run
//! use hexspell::pe::PE;
//!
//! let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
//! pe.write_file("out.exe").unwrap();
//! ```

// Standard
pub mod errors;
pub mod field;
pub mod reloc;
pub mod strings;
pub mod utils;
pub mod validation;
pub mod write;

pub mod elf; // ELF
pub mod macho;
/// Executable Formats
/// ==================
pub mod pe; // PE (Portable Executable) // Mach-O
