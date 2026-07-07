//! COFF file header (`IMAGE_FILE_HEADER`) — 20 bytes after PE signature.

use super::header::Architecture;
use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

/// COFF file header (`IMAGE_FILE_HEADER`) — 20 bytes after the `PE\0\0` signature.
#[derive(Debug)]
pub struct CoffFileHeader {
    /// Target machine (`IMAGE_FILE_MACHINE_*`).
    pub machine: Field<u16>,
    /// Number of section headers following the optional header.
    pub number_of_sections: Field<u16>,
    pub time_date_stamp: Field<u32>,
    pub pointer_to_symbol_table: Field<u32>,
    pub number_of_symbols: Field<u32>,
    /// Size of the optional header in bytes.
    pub size_of_optional_header: Field<u16>,
    pub characteristics: Field<u16>,
}

impl CoffFileHeader {
    /// Parses a COFF header at `offset` (immediately after `PE\0\0`).
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + 20 {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(CoffFileHeader {
            machine: Field::new(extract_u16(buffer, offset)?, offset, 2),
            number_of_sections: Field::new(extract_u16(buffer, offset + 2)?, offset + 2, 2),
            time_date_stamp: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            pointer_to_symbol_table: Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4),
            number_of_symbols: Field::new(extract_u32(buffer, offset + 12)?, offset + 12, 4),
            size_of_optional_header: Field::new(extract_u16(buffer, offset + 16)?, offset + 16, 2),
            characteristics: Field::new(extract_u16(buffer, offset + 18)?, offset + 18, 2),
        })
    }

    /// Returns the target architecture from the `machine` field.
    pub fn architecture(&self) -> Architecture {
        Architecture::from_u16(self.machine.value)
    }
}
