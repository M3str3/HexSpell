//! COFF line number tables (`IMAGE_LINENUMBER`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::section::PeSection;
use crate::utils::{extract_u16, extract_u32};

/// `LN_FDSYM` — line number record that references a symbol table index.
pub const LN_FDSYM: u16 = 0xffff;

/// `IMAGE_LINENUMBER` — 6 bytes in PE images.
pub struct LineNumberEntry {
    /// Symbol table index when [`Self::line_number`] is zero; otherwise section RVA.
    pub type_field: Field<u32>,
    /// Line number, or [`LN_FDSYM`] for a source-file symbol record.
    pub line_number: Field<u16>,
}

/// Line number table attached to one section header.
pub struct LineNumberBlock {
    /// Section index in the PE section table.
    pub section_index: usize,
    /// Absolute file offset of the first `IMAGE_LINENUMBER`.
    pub offset: usize,
    /// Line number records.
    pub entries: Vec<LineNumberEntry>,
}

impl LineNumberEntry {
    /// Size of `IMAGE_LINENUMBER` in bytes.
    pub const SIZE: usize = 6;

    /// Parses one line number record at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(LineNumberEntry {
            type_field: Field::new(extract_u32(buffer, offset)?, offset, 4),
            line_number: Field::new(extract_u16(buffer, offset + 4)?, offset + 4, 2),
        })
    }

    /// Returns `true` when this record marks the start of a source file (`Linenumber == 0`).
    pub fn is_source_file(&self) -> bool {
        self.line_number.value == 0
    }

    /// Returns `true` when this record maps a line to an RVA (`Linenumber != 0`).
    pub fn is_line_mapping(&self) -> bool {
        self.line_number.value != 0
    }
}

impl LineNumberBlock {
    /// Parses line numbers referenced by `section`.
    pub fn parse(
        buffer: &[u8],
        section_index: usize,
        section: &PeSection,
    ) -> Result<Self, FileParseError> {
        let count = section.number_of_linenumbers.value as usize;
        let offset = section.pointer_to_linenumbers.value as usize;
        if count == 0 || offset == 0 {
            return Ok(LineNumberBlock {
                section_index,
                offset,
                entries: Vec::new(),
            });
        }

        let end = offset
            .checked_add(count * LineNumberEntry::SIZE)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            entries.push(LineNumberEntry::parse(
                buffer,
                offset + i * LineNumberEntry::SIZE,
            )?);
        }

        Ok(LineNumberBlock {
            section_index,
            offset,
            entries,
        })
    }
}
