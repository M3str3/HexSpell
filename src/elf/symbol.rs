//! ELF symbol tables (`Elf32_Sym` / `Elf64_Sym`).
//!
//! [`SymbolEntry`] wraps the ELF32 and ELF64 layouts. Symbols live in `.symtab` (static) and
//! `.dynsym` (dynamic); names are resolved through the linked string table (`.strtab` / `.dynstr`).
//! Parsing is read-only: every field is a [`Field`] with its real file offset so callers can patch
//! the underlying buffer later.

use super::header::ElfClass;
use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field, FieldMut, NumericFieldMut};

/// `STB_LOCAL` binding.
pub const STB_LOCAL: u8 = 0;
/// `STB_GLOBAL` binding.
pub const STB_GLOBAL: u8 = 1;
/// `STB_WEAK` binding.
pub const STB_WEAK: u8 = 2;

/// `STT_NOTYPE` — unspecified type.
pub const STT_NOTYPE: u8 = 0;
/// `STT_OBJECT` — data object.
pub const STT_OBJECT: u8 = 1;
/// `STT_FUNC` — function.
pub const STT_FUNC: u8 = 2;
/// `STT_SECTION` — associated with a section.
pub const STT_SECTION: u8 = 3;
/// `STT_FILE` — source file name.
pub const STT_FILE: u8 = 4;

/// ELF32 symbol fields (`Elf32_Sym`, 16 bytes).
#[derive(Debug)]
pub struct Sym32Fields {
    pub st_name: Field<u32>,
    pub st_value: Field<u32>,
    pub st_size: Field<u32>,
    pub st_info: Field<u8>,
    pub st_other: Field<u8>,
    pub st_shndx: Field<u16>,
}

/// ELF64 symbol fields (`Elf64_Sym`, 24 bytes).
#[derive(Debug)]
pub struct Sym64Fields {
    pub st_name: Field<u32>,
    pub st_info: Field<u8>,
    pub st_other: Field<u8>,
    pub st_shndx: Field<u16>,
    pub st_value: Field<u64>,
    pub st_size: Field<u64>,
}

/// Symbol table entry — ELF32 or ELF64 variant.
///
/// Field order differs between classes; the accessors hide the layout difference.
#[derive(Debug)]
pub enum SymbolEntry {
    Sym32(Sym32Fields),
    Sym64(Sym64Fields),
}

impl SymbolEntry {
    /// On-disk size of a symbol entry for `class`.
    pub fn size_of(class: ElfClass) -> usize {
        match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        }
    }

    /// `st_name` — offset into the linked string table.
    pub fn st_name(&self) -> u32 {
        match self {
            SymbolEntry::Sym32(f) => f.st_name.value,
            SymbolEntry::Sym64(f) => f.st_name.value,
        }
    }

    pub fn st_name_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SymbolEntry::Sym32(f) => FieldMut::<u32>::new(&mut f.st_name),
            SymbolEntry::Sym64(f) => FieldMut::<u32>::new(&mut f.st_name),
        }
    }

    /// `st_value` — symbol value (address or offset).
    pub fn st_value(&self) -> u64 {
        match self {
            SymbolEntry::Sym32(f) => f.st_value.value as u64,
            SymbolEntry::Sym64(f) => f.st_value.value,
        }
    }

    pub fn st_value_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SymbolEntry::Sym32(f) => NumericFieldMut::U32(&mut f.st_value),
            SymbolEntry::Sym64(f) => NumericFieldMut::U64(&mut f.st_value),
        }
    }

    /// `st_size` — symbol size in bytes (`0` if unknown).
    pub fn st_size(&self) -> u64 {
        match self {
            SymbolEntry::Sym32(f) => f.st_size.value as u64,
            SymbolEntry::Sym64(f) => f.st_size.value,
        }
    }

    pub fn st_size_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SymbolEntry::Sym32(f) => NumericFieldMut::U32(&mut f.st_size),
            SymbolEntry::Sym64(f) => NumericFieldMut::U64(&mut f.st_size),
        }
    }

    /// `st_info` — packed binding (`high 4 bits`) and type (`low 4 bits`).
    pub fn st_info(&self) -> u8 {
        match self {
            SymbolEntry::Sym32(f) => f.st_info.value,
            SymbolEntry::Sym64(f) => f.st_info.value,
        }
    }

    /// `st_other` — visibility byte.
    pub fn st_other(&self) -> u8 {
        match self {
            SymbolEntry::Sym32(f) => f.st_other.value,
            SymbolEntry::Sym64(f) => f.st_other.value,
        }
    }

    /// `st_shndx` — section index the symbol is defined in.
    pub fn st_shndx(&self) -> u16 {
        match self {
            SymbolEntry::Sym32(f) => f.st_shndx.value,
            SymbolEntry::Sym64(f) => f.st_shndx.value,
        }
    }

    /// Symbol binding from the high nibble of `st_info` (`STB_*`).
    pub fn binding(&self) -> u8 {
        self.st_info() >> 4
    }

    /// Symbol type from the low nibble of `st_info` (`STT_*`).
    pub fn symbol_type(&self) -> u8 {
        self.st_info() & 0xf
    }

    /// Parses a symbol table starting at `offset` with `count` entries.
    pub(crate) fn parse_table(
        buffer: &[u8],
        offset: usize,
        count: usize,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<Vec<SymbolEntry>, FileParseError> {
        let ent_size = Self::size_of(class);
        let mut symbols = Vec::with_capacity(count);

        for i in 0..count {
            let base = offset + i * ent_size;
            if buffer.len() < base + ent_size {
                return Err(FileParseError::BufferOverflow);
            }

            let entry = match class {
                ElfClass::Elf32 => SymbolEntry::Sym32(Sym32Fields {
                    st_name: Field::new(order.read_u32(buffer, base)?, base, 4),
                    st_value: Field::new(order.read_u32(buffer, base + 4)?, base + 4, 4),
                    st_size: Field::new(order.read_u32(buffer, base + 8)?, base + 8, 4),
                    st_info: Field::new(buffer[base + 12], base + 12, 1),
                    st_other: Field::new(buffer[base + 13], base + 13, 1),
                    st_shndx: Field::new(order.read_u16(buffer, base + 14)?, base + 14, 2),
                }),
                ElfClass::Elf64 => SymbolEntry::Sym64(Sym64Fields {
                    st_name: Field::new(order.read_u32(buffer, base)?, base, 4),
                    st_info: Field::new(buffer[base + 4], base + 4, 1),
                    st_other: Field::new(buffer[base + 5], base + 5, 1),
                    st_shndx: Field::new(order.read_u16(buffer, base + 6)?, base + 6, 2),
                    st_value: Field::new(order.read_u64(buffer, base + 8)?, base + 8, 8),
                    st_size: Field::new(order.read_u64(buffer, base + 16)?, base + 16, 8),
                }),
            };
            symbols.push(entry);
        }

        Ok(symbols)
    }
}

/// A parsed symbol table plus the file offset of its linked string table.
pub struct SymbolTable {
    /// File offset where the symbol array starts.
    pub offset: usize,
    /// File offset of the linked string table (`.strtab` / `.dynstr`).
    pub strtab_offset: usize,
    /// Parsed symbol entries in file order.
    pub symbols: Vec<SymbolEntry>,
}

impl SymbolTable {
    /// Resolves the name of `symbol` via the linked string table.
    pub fn name(&self, buffer: &[u8], symbol: &SymbolEntry) -> Result<String, FileParseError> {
        super::read_str_at(buffer, self.strtab_offset + symbol.st_name() as usize)
    }
}
