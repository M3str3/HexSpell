//! COFF section relocation entries (`IMAGE_RELOCATION`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::section::PeSection;
use crate::utils::{extract_u16, extract_u32};

/// `IMAGE_REL_I386_DIR32` (x86).
pub const IMAGE_REL_I386_DIR32: u16 = 0x0006;
/// `IMAGE_REL_AMD64_ADDR64` (x64).
pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;

/// `IMAGE_RELOCATION` — 10 bytes in PE images.
#[derive(Debug, Clone)]
pub struct SectionRelocation {
    /// RVA of the relocation (`VirtualAddress`).
    pub virtual_address: Field<u32>,
    /// Symbol table index (`SymbolTableIndex`).
    pub symbol_table_index: Field<u32>,
    /// Relocation type (`Type`).
    pub reloc_type: Field<u16>,
}

/// Relocations attached to one section header.
pub struct SectionRelocationBlock {
    /// Section index in the PE section table.
    pub section_index: usize,
    /// Absolute file offset of the first relocation entry.
    pub offset: usize,
    /// Relocation entries.
    pub entries: Vec<SectionRelocation>,
}

impl SectionRelocation {
    /// Size of `IMAGE_RELOCATION` in bytes.
    pub const SIZE: usize = 10;

    /// Parses one relocation at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(SectionRelocation {
            virtual_address: Field::new(extract_u32(buffer, offset)?, offset, 4),
            symbol_table_index: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            reloc_type: Field::new(extract_u16(buffer, offset + 8)?, offset + 8, 2),
        })
    }
}

impl SectionRelocationBlock {
    /// Parses relocations referenced by `section`.
    pub fn parse(
        buffer: &[u8],
        section_index: usize,
        section: &PeSection,
    ) -> Result<Self, FileParseError> {
        let count = section.number_of_relocations.value as usize;
        let offset = section.pointer_to_relocations.value as usize;
        if count == 0 || offset == 0 {
            return Ok(SectionRelocationBlock {
                section_index,
                offset,
                entries: Vec::new(),
            });
        }

        let end = offset
            .checked_add(count * SectionRelocation::SIZE)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            entries.push(SectionRelocation::parse(
                buffer,
                offset + i * SectionRelocation::SIZE,
            )?);
        }

        Ok(SectionRelocationBlock {
            section_index,
            offset,
            entries,
        })
    }
}
