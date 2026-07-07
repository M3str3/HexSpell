//! ELF relocation tables (`.rel` / `.rela`).
//!
//! [`RelocationEntry`] wraps `Elf32_Rel`, `Elf64_Rel`, `Elf32_Rela` and `Elf64_Rela`. Each field is
//! a [`Field`] with its real file offset. `r_info` packs the symbol index and relocation type;
//! use [`RelocationEntry::symbol`] and [`RelocationEntry::reloc_type`] to unpack them.

use super::header::ElfClass;
use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// ELF32 relocation fields (with or without addend).
#[derive(Debug, Clone)]
pub struct Rel32Fields {
    pub r_offset: Field<u32>,
    pub r_info: Field<u32>,
    /// Present only for `.rela` sections.
    pub r_addend: Option<Field<u32>>,
}

/// ELF64 relocation fields (with or without addend).
#[derive(Debug, Clone)]
pub struct Rel64Fields {
    pub r_offset: Field<u64>,
    pub r_info: Field<u64>,
    /// Present only for `.rela` sections.
    pub r_addend: Option<Field<u64>>,
}

/// Relocation entry — ELF32 or ELF64 variant.
///
/// `.rel` entries have no addend; `.rela` entries carry one. The accessors hide the difference.
#[derive(Debug, Clone)]
pub enum RelocationEntry {
    Rel32(Rel32Fields),
    Rel64(Rel64Fields),
}

impl RelocationEntry {
    /// On-disk size of an entry for `class` (`with_addend` selects `.rela`).
    pub fn size_of(class: ElfClass, with_addend: bool) -> usize {
        match (class, with_addend) {
            (ElfClass::Elf32, false) => 8,
            (ElfClass::Elf32, true) => 12,
            (ElfClass::Elf64, false) => 16,
            (ElfClass::Elf64, true) => 24,
        }
    }

    /// `r_offset` — location to apply the relocation (address or offset).
    pub fn r_offset(&self) -> u64 {
        match self {
            RelocationEntry::Rel32(f) => f.r_offset.value as u64,
            RelocationEntry::Rel64(f) => f.r_offset.value,
        }
    }

    /// Raw `r_info` — packed symbol index and relocation type.
    pub fn r_info(&self) -> u64 {
        match self {
            RelocationEntry::Rel32(f) => f.r_info.value as u64,
            RelocationEntry::Rel64(f) => f.r_info.value,
        }
    }

    /// `r_addend` for `.rela` entries; `None` for `.rel`.
    pub fn r_addend(&self) -> Option<i64> {
        match self {
            RelocationEntry::Rel32(f) => f.r_addend.as_ref().map(|a| a.value as i32 as i64),
            RelocationEntry::Rel64(f) => f.r_addend.as_ref().map(|a| a.value as i64),
        }
    }

    /// Symbol table index from `r_info`.
    ///
    /// ELF32 uses the high 24 bits; ELF64 uses the high 32 bits.
    pub fn symbol(&self) -> u32 {
        match self {
            RelocationEntry::Rel32(f) => f.r_info.value >> 8,
            RelocationEntry::Rel64(f) => (f.r_info.value >> 32) as u32,
        }
    }

    /// Relocation type from `r_info`.
    ///
    /// ELF32 uses the low 8 bits; ELF64 uses the low 32 bits.
    pub fn reloc_type(&self) -> u32 {
        match self {
            RelocationEntry::Rel32(f) => f.r_info.value & 0xff,
            RelocationEntry::Rel64(f) => (f.r_info.value & 0xffff_ffff) as u32,
        }
    }

    /// Parses a relocation table starting at `offset` with `count` entries.
    pub(crate) fn parse_table(
        buffer: &[u8],
        offset: usize,
        count: usize,
        with_addend: bool,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<Vec<RelocationEntry>, FileParseError> {
        let ent_size = Self::size_of(class, with_addend);
        let mut entries = Vec::with_capacity(count);

        for i in 0..count {
            let base = offset + i * ent_size;
            if buffer.len() < base + ent_size {
                return Err(FileParseError::BufferOverflow);
            }

            let entry = match class {
                ElfClass::Elf32 => RelocationEntry::Rel32(Rel32Fields {
                    r_offset: Field::new(order.read_u32(buffer, base)?, base, 4),
                    r_info: Field::new(order.read_u32(buffer, base + 4)?, base + 4, 4),
                    r_addend: if with_addend {
                        Some(Field::new(order.read_u32(buffer, base + 8)?, base + 8, 4))
                    } else {
                        None
                    },
                }),
                ElfClass::Elf64 => RelocationEntry::Rel64(Rel64Fields {
                    r_offset: Field::new(order.read_u64(buffer, base)?, base, 8),
                    r_info: Field::new(order.read_u64(buffer, base + 8)?, base + 8, 8),
                    r_addend: if with_addend {
                        Some(Field::new(order.read_u64(buffer, base + 16)?, base + 16, 8))
                    } else {
                        None
                    },
                }),
            };
            entries.push(entry);
        }

        Ok(entries)
    }
}
