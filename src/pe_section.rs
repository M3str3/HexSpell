use crate::utils::{extract_u16,extract_u32};
use crate::field::Field;
use crate::pe_errors::PeError;

pub struct PeSection {
    pub name: Field<String>,
    pub virtual_size: Field<u32>,
    pub virtual_address: Field<u32>,
    pub size_of_raw_data: Field<u32>,
    pub pointer_to_raw_data: Field<u32>,
    pub pointer_to_relocations: Field<u32>,
    pub pointer_to_linenumbers: Field<u32>,
    pub number_of_relocations: Field<u16>,
    pub number_of_linenumbers: Field<u16>,
    pub characteristics: Field<u32>,
}

impl PeSection {
    /// Parses a section of PE file from a buffer and the offset.
    ///
    /// ## Arguments
    /// * `buffer` - A byte vector containing the PE file data.
    /// * `offset` - A byte vector containing the PE file data.
    ///
    /// ## Returns
    /// A `io::Result` with PeSection
    pub fn parse_section(buffer: &[u8], offset: usize) -> Result<Self, PeError> {
        if buffer.len() < offset + 40 {
            return Err(PeError::BufferOverflow);
        }

        let name = String::from_utf8_lossy(&buffer[offset..offset + 8]).trim_end_matches('\0').to_string();
        let virtual_size = extract_u32(buffer, offset + 8)?;
        let virtual_address = extract_u32(buffer, offset + 12)?;
        let size_of_raw_data = extract_u32(buffer, offset + 16)?;
        let pointer_to_raw_data = extract_u32(buffer, offset + 20)?;
        let pointer_to_relocations = extract_u32(buffer, offset + 24)?;
        let pointer_to_linenumbers = extract_u32(buffer, offset + 28)?;
        let number_of_relocations = extract_u16(buffer, offset + 32)?;
        let number_of_linenumbers = extract_u16(buffer, offset + 34)?;
        let characteristics = extract_u32(buffer, offset + 36)?;

        Ok(PeSection {
            name: Field::new(name, offset, 8),
            virtual_size: Field::new(virtual_size, offset + 8, 4),
            virtual_address: Field::new(virtual_address, offset + 12, 4),
            size_of_raw_data: Field::new(size_of_raw_data, offset + 16, 4),
            pointer_to_raw_data: Field::new(pointer_to_raw_data, offset + 20, 4),
            pointer_to_relocations: Field::new(pointer_to_relocations, offset + 24, 4),
            pointer_to_linenumbers: Field::new(pointer_to_linenumbers, offset + 28, 4),
            number_of_relocations: Field::new(number_of_relocations, offset + 32, 2),
            number_of_linenumbers: Field::new(number_of_linenumbers, offset + 34, 2),
            characteristics: Field::new(characteristics, offset + 36, 4),
        })
    }
}